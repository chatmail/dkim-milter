use crate::{
    auth_results,
    config::{Config, OperationMode, SignatureConfig, SigningSenders},
    format::{self, EmailAddr},
    resolver::Resolver,
};
use bstr::ByteSlice;
use indymilter::{ContextActions, Status};
use std::{borrow::Cow, cmp, collections::HashSet, error::Error, mem, net::IpAddr, sync::Arc};
use tracing::{debug, error, info};
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

// TODO
pub struct Session {
    config: Arc<Config>,

    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,

    pub auth: bool,
    header_bytes: usize,
    from_address: Option<Result<EmailAddr, FromAddrError>>,

    mode: Mode,

    headers: Vec<(FieldName, FieldBody)>,
}

impl Session {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,

            ip: None,
            hostname: None,

            auth: false,
            header_bytes: 0,
            from_address: None,

            mode: Mode::Inactive,

            headers: vec![],
        }
    }

    pub fn abort_message(&mut self) {
        // TODO align abort and eom
        // reset everything except config, and connect-stage values ip and hostname
        self.auth = false;
        self.header_bytes = 0;
        self.from_address = None;
        self.mode = Mode::Inactive;
        self.headers = vec![];
    }

    pub fn handle_header(
        &mut self,
        id: &str,
        name: Cow<'_, str>,
        value: Vec<u8>,
    ) -> Result<Status, Box<dyn Error>> {
        // convert milter newlines to SMTP CRLF
        let value = value.replace("\n", "\r\n");

        // count and limit amount of header data that can be accumulated (DoS)
        const MAX_HEADER_LEN: usize = 512_000;

        // name + ':' + value + CRLF
        self.header_bytes = self.header_bytes.saturating_add(name.len() + value.len() + 3);
        if self.header_bytes > MAX_HEADER_LEN {
            debug!("{id}: too much header data");
            return Err("too much header data".into());
        }

        // extract From header
        if name.eq_ignore_ascii_case("From") {
            if self.from_address.is_some() {
                // if there was a From already, there are now multiple: invalidate
                debug!("{id}: repeated From header field, ignoring From");
                self.from_address = Some(Err(FromAddrError::Multiple));
            } else {
                match format::parse_header_from_address(&value) {
                    Ok(addr) => {
                        self.from_address = Some(Ok(addr));
                    }
                    Err(e) => {
                        debug!("{id}: unusable From header field: {e:?}");
                        self.from_address = Some(Err(FromAddrError::Syntax));
                    }
                }
            }
        }

        // update header fields, ignore unusable inputs
        if let (Ok(name), Ok(value)) = (FieldName::new(name), FieldBody::new(value)) {
            self.headers.push((name, value));
        }

        Ok(Status::Continue)
    }

    pub async fn prepare_processing(&mut self, id: &str) -> Result<Status, Box<dyn Error>> {
        let headers = mem::take(&mut self.headers);
        let headers = match HeaderFields::new(headers) {
            Ok(h) => h,
            Err(e) => {
                // For now, give up if inputs don't look like an email header at all
                debug!("{id}: unusable header fields: {e:?}");
                return Ok(Status::Accept);
            }
        };

        match self.config.mode {
            OperationMode::Auto | OperationMode::Sign => {
                // local and authenticated senders are authorised
                let authzd = self.ip.filter(|i| i.is_loopback()).is_some() || self.auth;

                let from_address = match &self.from_address {
                    Some(Ok(from_address)) => {
                        debug!("{id}: From address is: {from_address}");
                        Some(from_address)
                    }
                    _ => {
                        debug!("{id}: no usable From header field in message");
                        None
                    }
                };

                // TODO find matches in SigningSenders
                let matches = match from_address {
                    Some(from_address) => find_matching_senders(&self.config.signing_senders, from_address),
                    None => vec![],
                };

                // signing mode if authorised and right domain to sign in From
                self.mode = if authzd && !matches.is_empty() {
                    debug!("{id}: signing mode");
                    let signer = self.prepare_signer(headers, matches)?;
                    Mode::Signing(signer)
                } else {
                    if self.config.mode == OperationMode::Auto {
                        debug!("{id}: verifying mode");
                        match self.prepare_verifier(headers).await {
                            Some(verifier) => Mode::Verifying(verifier),
                            None => Mode::Inactive,
                        }
                    } else {
                        Mode::Inactive
                    }
                };
            }
            OperationMode::Verify => {
                debug!("{id}: verifying mode");
                self.mode = match self.prepare_verifier(headers).await {
                    Some(verifier) => Mode::Verifying(verifier),
                    None => Mode::Inactive,
                };
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

        // step through matches and create SignRequest for each match

        let mut requests = vec![];
        for match_ in matches {
            let domain = match_.domain;
            let selector = match_.selector;
            let key_name = match_.key_name;
            let signing_key = self.config.signing_keys.get(&key_name).unwrap();

            let key_type = signing_key.key_type();
            let signature_alg = SignatureAlgorithm::from_parts(key_type, HashAlgorithm::Sha256).unwrap();

            let mut request = SignRequest::new(domain, selector, signature_alg, signing_key.clone());

            let tmp_config = match_.signature_config.as_ref().unwrap_or(&self.config.signature_config);

            request.canonicalization = tmp_config.canonicalization;
            request.copy_headers = tmp_config.copy_headers;
            if tmp_config.limit_body_length {
                request.body_length = BodyLength::OnlyMessageLength;
            }

            let mut signed_headers: HashSet<_> = signer::get_default_signed_headers().into_iter().collect();
            signed_headers.insert(FieldName::new("Message-ID").unwrap());
            let oversigned_headers = HashSet::from([FieldName::new("From").unwrap()]);
            request.header_selection = HeaderSelection::Pick {
                include: signed_headers,
                oversign: OversignStrategy::Selected(oversigned_headers),
            };

            requests.push(request);
        }

        let signer = Signer::prepare_signing(requests, headers)
            .map_err(|_| "could not prepare signing")?;

        Ok(signer)
    }

    async fn prepare_verifier(&mut self, headers: HeaderFields) -> Option<Verifier> {
        let resolver = Resolver::new();

        let fail_if_expired = self.config.fail_if_expired;

        let config = verifier::Config {
            fail_if_expired,
            ..Default::default()
        };

        Verifier::process_headers(&resolver, &headers, &config).await
    }

    pub fn process_body_chunk(&mut self, chunk: &[u8]) -> Result<Status, Box<dyn Error>> {
        let status = match &mut self.mode {
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
        match mem::take(&mut self.mode) {
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
                    info!(
                        "{id}: verified signature from {}: {}",
                        get_domain_from_verification_result(sig),
                        sig.status.to_auth_results_kind()
                    );
                }

                if !sigs.is_empty() {
                    let ar = auth_results::assemble_auth_results(
                        self.config.authserv_id.as_deref().unwrap_or("localhost"),
                        sigs,
                    );

                    actions
                        .insert_header(0, "Authentication-Results", ar)
                        .await
                        .map_err(|_| "failed to insert header")?;
                }
            }
        }

        // TODO reset to beginning of per-message handling
        self.abort_message();

        Ok(Status::Continue)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SenderMatch {
    domain: DomainName,
    selector: Selector,
    key_name: String,
    signature_config: Option<SignatureConfig>,
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
                key_name: entry.key_name.clone(),
                signature_config: entry.signature_config.clone(),
            });
        }
    }

    matches
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

#[cfg(test)]
mod tests {
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
                    signature_config: None,
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
                signature_config: None,
            }
        ]);
    }
}
