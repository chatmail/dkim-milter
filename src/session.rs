use crate::{
    auth_results,
    config::{
        model::{
            OperationMode, SigningConfig, SigningConfigOverrides, SigningOverrides, SigningSenders,
            SignedHeaders,
        },
        RuntimeConfig,
    },
    format::{self, EmailAddr},
    resolver::Resolver,
};
use bstr::ByteSlice;
use indymilter::{ContextActions, Status};
use std::{borrow::Cow, cmp, collections::HashSet, error::Error, mem, net::IpAddr, sync::Arc};
use log::{debug, error, info};
use viadkim::{
    crypto::HashAlgorithm,
    header::{FieldBody, FieldName, HeaderFields},
    message_hash::BodyHasherStance,
    signature::{DomainName, Selector, SignatureAlgorithm},
    signer::{self, BodyLength, HeaderSelection, OversignStrategy, SignRequest, SigningStatus},
    verifier::{self, VerificationResult, VerificationStatus, VerifierError},
    Signer, SigningKey, Verifier,
};

#[derive(Default)]
pub enum Mode {
    #[default]
    Inactive,
    Signing(Signer<Arc<SigningKey>>),
    Verifying(Verifier),
}

enum FromAddrError {
    Syntax,
    Multiple,
}

#[derive(Default)]
struct ConnectionData {
    ip: Option<IpAddr>,
    hostname: Option<String>,
}

impl ConnectionData {
    fn new() -> Self {
        Default::default()
    }
}

#[derive(Default)]
struct MessageData {
    auth: bool,
    recipients: Vec<String>,
    header_bytes: usize,
    sender_address: Option<Result<EmailAddr, FromAddrError>>,
    from_addresses: Option<Result<Vec<EmailAddr>, FromAddrError>>,
    mode: Mode,
    headers: Vec<(FieldName, FieldBody)>,
}

impl MessageData {
    fn new() -> Self {
        Default::default()
    }
}

pub struct Session {
    runtime: Arc<RuntimeConfig>,

    conn: ConnectionData,
    message: Option<MessageData>,
}

impl Session {
    pub fn new(runtime: Arc<RuntimeConfig>) -> Self {
        Self {
            runtime,
            conn: ConnectionData::new(),
            message: None,
        }
    }

    pub fn init_connection(&mut self, ip: Option<IpAddr>, hostname: impl Into<String>) {
        self.conn.ip = ip;
        self.conn.hostname = Some(hostname.into());
    }

    pub fn init_message(&mut self) {
        self.message = Some(MessageData::new());
    }

    pub fn set_authenticated(&mut self) {
        self.message.as_mut().unwrap().auth = true;
    }

    pub fn add_recipient(&mut self, mut rcpt: String) {
        if let Some(s) = rcpt.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
            rcpt = s.into();
        }
        self.message.as_mut().unwrap().recipients.push(rcpt);
    }

    pub fn abort_message(&mut self) {
        self.message = None;
    }

    pub fn handle_header(
        &mut self,
        id: &str,
        name: Cow<'_, str>,
        value: Vec<u8>,
    ) -> Result<Status, Box<dyn Error>> {
        let message = match self.message.as_mut() {
            Some(message) => message,
            None => return Err("message context not available".into()),
        };

        // convert milter newlines to SMTP CRLF
        let value = value.replace("\n", "\r\n");

        // count and limit amount of header data that can be accumulated (DoS)
        const MAX_HEADER_LEN: usize = 512_000;

        // name + ':' + value + CRLF
        message.header_bytes = message.header_bytes.saturating_add(name.len() + value.len() + 3);
        if message.header_bytes > MAX_HEADER_LEN {
            debug!("{id}: too much header data");
            return Err("too much header data".into());
        }

        // extract Sender header
        if name.eq_ignore_ascii_case("Sender") {
            if message.sender_address.is_some() {
                debug!("{id}: repeated Sender header field, ignoring Sender");
                message.sender_address = Some(Err(FromAddrError::Multiple));
            } else {
                match format::parse_header_sender_address(&value) {
                    Ok(addr) => {
                        message.sender_address = Some(Ok(addr));
                    }
                    Err(e) => {
                        debug!("{id}: unusable Sender header field: {e:?}");
                        message.sender_address = Some(Err(FromAddrError::Syntax));
                    }
                }
            }
        }

        // extract From header
        if name.eq_ignore_ascii_case("From") {
            if message.from_addresses.is_some() {
                debug!("{id}: repeated From header field, ignoring From");
                message.from_addresses = Some(Err(FromAddrError::Multiple));
            } else {
                match format::parse_header_from_addresses(&value) {
                    Ok(addr) => {
                        message.from_addresses = Some(Ok(addr));
                    }
                    Err(e) => {
                        debug!("{id}: unusable From header field: {e:?}");
                        message.from_addresses = Some(Err(FromAddrError::Syntax));
                    }
                }
            }
        }

        // update header fields, ignore unusable inputs
        if let (Ok(name), Ok(value)) = (FieldName::new(name), FieldBody::new(value)) {
            message.headers.push((name, value));
        }

        Ok(Status::Continue)
    }

    pub async fn prepare_processing(&mut self, id: &str) -> Result<Status, Box<dyn Error>> {
        let message = match self.message.as_mut() {
            Some(message) => message,
            None => return Err("message context not available".into()),
        };

        let headers = mem::take(&mut message.headers);
        let headers = match HeaderFields::new(headers) {
            Ok(h) => h,
            Err(e) => {
                // For now, give up if inputs don't look like an email header at all
                debug!("{id}: unusable header fields: {e:?}");
                return Ok(Status::Accept);
            }
        };

        match self.runtime.config.mode {
            OperationMode::Auto | OperationMode::Sign => {
                // local and authenticated senders are authorised
                let authzd = self.conn.ip.filter(|i| i.is_loopback()).is_some() || message.auth;

                let sender = match &message.sender_address {
                    Some(Ok(sender_addr)) => Some(sender_addr),
                    Some(Err(_)) => None,
                    None => {
                        // fall back to From
                        match &message.from_addresses {
                            Some(Ok(from_addresses)) => {
                                if from_addresses.len() > 1 {
                                    None
                                } else {
                                    Some(from_addresses.first().unwrap())
                                }
                            }
                            Some(Err(_)) | None => None,
                        }
                    }
                };

                // TODO find matches in SigningSenders
                let matches = match sender {
                    Some(sender) => {
                        debug!("{id}: using sender address: {sender}");
                        find_matching_senders(&self.runtime.config.signing_senders, sender)
                    }
                    None => vec![],
                };

                // signing mode if authorised and right domain to sign in From
                let mode = if authzd && !matches.is_empty() {
                    debug!("{id}: signing mode");
                    let signer = self.prepare_signer(headers, matches)?;
                    Mode::Signing(signer)
                } else {
                    if self.runtime.config.mode == OperationMode::Auto {
                        debug!("{id}: verifying mode");
                        match self.prepare_verifier(headers).await {
                            Some(verifier) => Mode::Verifying(verifier),
                            None => Mode::Inactive,
                        }
                    } else {
                        Mode::Inactive
                    }
                };

                let message = self.message.as_mut().unwrap();
                message.mode = mode;
            }
            OperationMode::Verify => {
                debug!("{id}: verifying mode");
                let mode = match self.prepare_verifier(headers).await {
                    Some(verifier) => Mode::Verifying(verifier),
                    None => Mode::Inactive,
                };

                let message = self.message.as_mut().unwrap();
                message.mode = mode;
            }
        }

        Ok(Status::Continue)
    }

    fn prepare_signer(
        &mut self,
        headers: HeaderFields,
        matches: Vec<SenderMatch>,
    ) -> Result<Signer<Arc<SigningKey>>, Box<dyn Error>> {
        assert!(!matches.is_empty());

        // TODO
        // at this point there is one or more signature to be generated;
        // first check if there are config overrides for the recipients!

        let recipient_overrides = self.runtime.config.recipient_overrides.as_ref()
            .and_then(|overrides| find_matching_recipient_overrides(
                overrides,
                &self.message.as_ref().unwrap().recipients,
            ));

        // step through matches and create SignRequest for each match

        let mut requests = vec![];
        for match_ in matches {
            let domain = match_.domain;
            let selector = match_.selector;
            let signing_key = match_.key;

            let config = match (&match_.signing_config, &recipient_overrides) {
                (Some(c1), Some(c2)) => {
                    self.runtime.config.signing_config.combine_with(c1).combine_with(c2)
                }
                (Some(c), None) | (None, Some(c)) => {
                    self.runtime.config.signing_config.combine_with(c)
                }
                (None, None) => {
                    self.runtime.config.signing_config.clone()
                }
            };

            let request = make_sign_request(&config, domain, selector, signing_key);

            requests.push(request);
        }

        let signer = Signer::prepare_signing(requests, headers)
            .map_err(|_| "could not prepare signing")?;

        Ok(signer)
    }

    async fn prepare_verifier(&mut self, headers: HeaderFields) -> Option<Verifier> {
        let fail_if_expired = self.runtime.config.fail_if_expired;

        let config = verifier::Config {
            fail_if_expired,
            ..Default::default()
        };

        match &self.runtime.resolver {
            Resolver::Live(r) => {
                Verifier::process_header(r, &headers, &config).await
            }
            Resolver::Mock(r) => {
                Verifier::process_header(r.as_ref(), &headers, &config).await
            }
        }
    }

    pub fn process_body_chunk(&mut self, chunk: &[u8]) -> Result<Status, Box<dyn Error>> {
        let message = match self.message.as_mut() {
            Some(message) => message,
            None => return Err("message context not available".into()),
        };

        let status = match &mut message.mode {
            Mode::Inactive => return Ok(Status::Skip),
            Mode::Signing(signer) => {
                signer.body_chunk(chunk)
            }
            Mode::Verifying(verifier) => {
                verifier.body_chunk(chunk)
            }
        };

        Ok(if let BodyHasherStance::Done = status {
            Status::Skip
        } else {
            Status::Continue
        })
    }

    pub async fn finish_message(
        &mut self,
        id: &str,
        actions: &impl ContextActions,
    ) -> Result<Status, Box<dyn Error>> {
        let message = match self.message.take() {
            Some(message) => message,
            None => return Err("message context not available".into()),
        };

        match message.mode {
            Mode::Inactive => {}
            Mode::Signing(signer) => {
                let sigs = signer.finish().await;

                for res in sigs {
                    let sstatus = res.status;
                    match sstatus {
                        SigningStatus::Error { error } => {
                            // TODO state domain/selector
                            let _e = error;
                            error!("{id}: failed to sign message");
                        }
                        SigningStatus::Success { signature, header_name, header_value } => {
                            info!("{id}: signed message for {}", signature.domain);

                            let name = header_name;
                            let value = header_value;

                            // convert SMTP CRLF to milter line endings
                            let value = value.replace("\r\n", "\n");

                            actions
                                .insert_header(0, name, value)
                                .await
                                .map_err(|_| "failed to insert header")?;
                        }
                    }
                }
            }
            Mode::Verifying(verifier) => {
                let sigs = verifier.finish();

                for sig in &sigs {
                    // TODO

                    let reason;
                    let reason = if let Some(r) = auth_results::auth_results_reason_from_status(&sig.status) {
                        reason = format!(" ({r})");
                        &reason
                    } else {
                        ""
                    };

                    info!(
                        "{id}: verified signature from {}: {}{}",
                        get_domain_from_verification_result(sig),
                        sig.status.to_auth_results_kind(),
                        reason
                    );
                }

                if !sigs.is_empty() {
                    let ar = auth_results::assemble_auth_results(
                        self.runtime.config.authserv_id.as_deref().unwrap_or("localhost"),
                        sigs,
                    );

                    actions
                        .insert_header(0, "Authentication-Results", ar)
                        .await
                        .map_err(|_| "failed to insert header")?;
                }
            }
        }

        Ok(Status::Continue)
    }
}

#[derive(Clone, Debug)]
struct SenderMatch {
    domain: DomainName,
    selector: Selector,
    key: Arc<SigningKey>,
    signing_config: Option<SigningConfigOverrides>,
}

fn find_matching_senders(
    signing_senders: &SigningSenders,
    from_address: &EmailAddr,
) -> Vec<SenderMatch> {
    let EmailAddr { local_part, domain } = from_address;

    // TODO

    let addr = format!("{local_part}@{domain}");
    //let _domain: &str = domain.as_ref();

    let mut matches = vec![];

    for entry in &signing_senders.entries {
        if entry.sender_expr.is_match(&addr) {
            matches.push(SenderMatch {
                domain: entry.domain.clone(),
                selector: entry.selector.clone(),
                key: entry.key_name.clone(),
                signing_config: entry.signing_config.clone(),
            });
        }
    }

    matches
}

fn find_matching_recipient_overrides(
    recipient_overrides: &SigningOverrides,
    recipients: &[String],
    // from_address: &EmailAddr,
) -> Option<SigningConfigOverrides> {
    for recipient in recipients {
        // TODO ensure is parsable as email addr
        for overrides in &recipient_overrides.entries {
            if overrides.expr.is_match(recipient) {
                return Some(overrides.config.clone());
            }
        }
    }

    None
}

fn make_sign_request(
    config: &SigningConfig,
    domain: DomainName,
    selector: Selector,
    signing_key: Arc<SigningKey>,
) -> SignRequest<Arc<SigningKey>> {
    let key_type = signing_key.key_type();

    let signature_alg = SignatureAlgorithm::from_parts(key_type, HashAlgorithm::Sha256).unwrap();

    let mut request = SignRequest::new(domain, selector, signature_alg, signing_key);

    request.canonicalization = config.canonicalization;
    request.copy_headers = config.copy_headers;
    if config.limit_body_length {
        request.body_length = BodyLength::OnlyMessageLength;
    }

    let oversigned_headers = HashSet::from([FieldName::new("From").unwrap()]);

    match &config.signed_headers {
        SignedHeaders::Pick(names) => {
            let signed_headers: HashSet<_> = names.into_iter().map(|n| n.as_ref().clone()).collect();
            request.header_selection = HeaderSelection::Pick {
                include: signed_headers,
                oversign: OversignStrategy::Selected(oversigned_headers),
            };
        }
        SignedHeaders::PickWithDefault(names) => {
            let mut signed_headers: HashSet<_> = signer::get_default_signed_headers().into_iter().collect();
            for name in names {
                signed_headers.insert(name.as_ref().clone());
            }
            request.header_selection = HeaderSelection::Pick {
                include: signed_headers,
                oversign: OversignStrategy::Selected(oversigned_headers),
            };
        }
        SignedHeaders::All => {
            let excluded_headers: HashSet<_> = signer::get_default_excluded_headers().into_iter().collect();
            request.header_selection = HeaderSelection::All {
                exclude: excluded_headers,
                oversign: OversignStrategy::Selected(oversigned_headers),
            };
        }
    }

    request
}

pub fn get_domain_from_verification_result(res: &VerificationResult) -> String {
    match &res.signature {
        Some(s) => s.domain.to_string(),
        None => {
            if let VerificationStatus::Failure(VerifierError::DkimSignatureHeaderFormat(e)) = &res.status {
                if let Some(d) = &e.domain {
                    return d.to_string();
                }
            }
            "unknown".to_string()
        }
    }
}

pub fn get_signature_prefix_from_verification_result(res: &VerificationResult) -> Option<String> {
    match &res.signature {
        Some(sig) => {
            let s = viadkim::encode_binary(&sig.signature_data);
            let s = &s[..(cmp::min(8, s.len()))];
            Some(s.into())
        }
        None => {
            if let VerificationStatus::Failure(VerifierError::DkimSignatureHeaderFormat(e)) =
                &res.status
            {
                if let Some(s) = &e.signature_data_base64 {
                    let s = &s[..(cmp::min(8, s.len()))];
                    return Some(s.into());
                }
            }
            None
        }
    }
}

// TODO
#[cfg(test)]
mod tests {
    /*
    use super::*;
    use crate::config::SenderEntry;
    use regex::Regex;

    #[test]
    fn find_matching_senders_ok() {
        let domain = DomainName::new("example.com").unwrap();
        let selector = Selector::new("sel1").unwrap();
        let key_name = String::from("mykey1");

        let signing_senders = SigningSenders {
            entries: vec![
                SenderEntry {
                    sender_expr: Regex::new(".*@mail.example.com").unwrap(),
                    domain: domain.clone(),
                    selector: selector.clone(),
                    key_name: key_name.clone(),
                    signing_config: None,
                }
            ],
        };

        let from_address = EmailAddr::new("itsame@mail.example.com").unwrap();

        let matches = find_matching_senders(&signing_senders, &from_address);

        assert_eq!(matches, vec![
            SenderMatch {
                domain,
                selector,
                key_name,
                signing_config: None,
            }
        ]);
    }
    */
}
