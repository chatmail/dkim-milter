use crate::{
    auth_results,
    config::{
        model::{ConfigOverrides, OperationMode, PartialSigningConfig, SigningSenders},
        Config, SessionConfig,
    },
    format::{self, MailAddr},
    sign::Signer,
    verify::Verifier,
};
use bstr::ByteSlice;
use indymilter::{ActionError, ContextActions, SetErrorReply, Status};
use log::{debug, info};
use std::{borrow::Cow, error::Error, ffi::CString, mem, net::IpAddr, sync::Arc};
use viadkim::{
    crypto::SigningKey,
    header::{self, FieldBody, FieldName, HeaderFields},
    signature::{DomainName, Selector},
};

#[derive(Default)]
enum Mode {
    #[default]
    Inactive,
    Signing(Signer),
    Verifying(Verifier),
}

pub enum SenderAddrError {
    Syntax,
    Multiple,
}

#[derive(Default)]
struct ConnectionData {
    ip: Option<IpAddr>,
    hostname: Option<String>,
    connection_overrides: Option<ConfigOverrides>,
}

impl ConnectionData {
    fn new() -> Self {
        Default::default()
    }

    fn hostname(&self) -> &str {
        self.hostname.as_deref().expect("no hostname available")
    }
}

#[derive(Default)]
struct MessageData {
    auth: bool,
    recipients: Vec<String>,
    header_bytes: usize,
    sender_address: Option<Result<MailAddr, SenderAddrError>>,
    from_addresses: Option<Result<Vec<MailAddr>, SenderAddrError>>,
    auth_results_i: usize,
    auth_results_deletions: Vec<usize>,
    mode: Mode,
    headers: Vec<(FieldName, FieldBody)>,
}

impl MessageData {
    fn new() -> Self {
        Default::default()
    }
}

pub struct Session {
    session_config: Arc<SessionConfig>,

    can_skip: bool,
    conn: ConnectionData,
    message: Option<MessageData>,
}

impl Session {
    pub fn new(session_config: Arc<SessionConfig>, can_skip: bool) -> Self {
        Self {
            session_config,
            can_skip,
            conn: ConnectionData::new(),
            message: None,
        }
    }

    pub fn can_skip(&self) -> bool {
        self.can_skip
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

    pub fn process_header(
        &mut self,
        id: &str,
        name: Cow<'_, str>,
        value: Vec<u8>,
    ) -> Result<Status, Box<dyn Error>> {
        let message = match self.message.as_mut() {
            Some(message) => message,
            None => return Err("message context not available".into()),
        };

        let config = &self.session_config.config;

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
                message.sender_address = Some(Err(SenderAddrError::Multiple));
            } else {
                match format::parse_sender_address(&value) {
                    Ok(addr) => {
                        message.sender_address = Some(Ok(addr));
                    }
                    Err(e) => {
                        debug!("{id}: unusable Sender header field: {e}");
                        message.sender_address = Some(Err(SenderAddrError::Syntax));
                    }
                }
            }
        }

        // extract From header
        if name.eq_ignore_ascii_case("From") {
            if message.from_addresses.is_some() {
                debug!("{id}: repeated From header field, ignoring From");
                message.from_addresses = Some(Err(SenderAddrError::Multiple));
            } else {
                match format::parse_from_addresses(&value) {
                    Ok(addr) => {
                        message.from_addresses = Some(Ok(addr));
                    }
                    Err(e) => {
                        debug!("{id}: unusable From header field: {e}");
                        message.from_addresses = Some(Err(SenderAddrError::Syntax));
                    }
                }
            }
        }

        // look for incoming forged Authentication-Results
        if config.delete_incoming_authentication_results
            && name.eq_ignore_ascii_case("Authentication-Results")
        {
            message.auth_results_i += 1;

            if let Some(incoming_aid) = auth_results::extract_authserv_id(&value) {
                let aid = authserv_id(config, self.conn.hostname());
                if eq_authserv_ids(aid, &incoming_aid) {
                    debug!(
                        "{id}: recognized own authserv-id in incoming Authentication-Results header instance {}",
                        message.auth_results_i
                    );
                    message.auth_results_deletions.push(message.auth_results_i);
                }
            } else {
                debug!(
                    "{id}: failed to parse incoming Authentication-Results header instance {}",
                    message.auth_results_i
                );
            }
        }

        // update header fields, ignore unusable inputs
        match (FieldName::new(name), FieldBody::new(value)) {
            (Ok(name), Ok(value)) => {
                message.headers.push((name, value));
            }
            _ => {
                debug!("{id}: ignoring ill-formed header field");
            }
        }

        Ok(Status::Continue)
    }

    pub async fn init_processing(&mut self, id: &str) -> Result<Status, Box<dyn Error>> {
        let message = match self.message.as_mut() {
            Some(message) => message,
            None => return Err("message context not available".into()),
        };

        let headers = mem::take(&mut message.headers);
        let headers = match HeaderFields::new(headers) {
            Ok(h) => h,
            Err(_) => {
                // For now, give up if inputs don't look like an email header at all
                debug!("{id}: accepted message with unusable header fields");
                return Ok(Status::Accept);
            }
        };

        // Minimalistic interpretation of RFC 6376, section 3.8: ‘Signers and
        // Verifiers SHOULD take reasonable steps to ensure that the messages
        // they are processing are valid according to [RFC5322], [RFC2045], and
        // any other relevant message format standards.’
        if let Err(e) = header::validate_rfc5322(&headers) {
            // For now, simply log that we are proceeding with an ill-formed header.
            info!("{id}: proceeding with header not conforming to RFC 5322: {e}");
            // TODO perhaps also check "Sender MUST occur with multi-address From" here?
        }

        // A trusted sender is eligible for signing, and is not eligible for
        // verifying.
        let authorized = is_trusted_sender(id, &self.session_config.config, self.conn.ip, message.auth);

        let mode = match self.session_config.config.mode {
            mode @ (OperationMode::Sign | OperationMode::Auto) => {
                if authorized {
                    let sender = extract_sender(
                        id,
                        message.sender_address.as_ref(),
                        message.from_addresses.as_ref(),
                    );

                    let matches = match sender {
                        Some(sender) => find_matching_senders(&self.session_config.config.signing_senders, sender),
                        None => vec![],
                    };

                    // signing mode if authorised and right domain to sign in From
                    if matches.is_empty() {
                        debug!("{id}: accepted message from trusted sender not configured for signing");
                        return Ok(Status::Accept);
                    } else {
                        // TODO cloning b/c of borrow checker
                        let sender: MailAddr = sender.unwrap().clone();

                        self.enter_signing_mode(id, headers, &sender, matches)?
                    }
                } else if mode == OperationMode::Auto {
                    self.enter_verifying_mode(id, headers).await
                } else {
                    debug!("{id}: accepted message from untrusted sender");
                    return Ok(Status::Accept);
                }
            }
            OperationMode::Verify => {
                if authorized {
                    debug!("{id}: accepted message from trusted sender");
                    return Ok(Status::Accept);
                } else {
                    self.enter_verifying_mode(id, headers).await
                }
            }
        };

        let message = self.message.as_mut().unwrap();
        message.mode = mode;

        Ok(Status::Continue)
    }

    fn enter_signing_mode(
        &mut self,
        id: &str,
        headers: HeaderFields,
        sender: &MailAddr,
        matches: Vec<SenderMatch>,
    ) -> Result<Mode, Box<dyn Error>> {
        debug!("{id}: entered signing mode");

        // Connection overrides should be calculated only once
        // for the connection and then cached.
        // let (connection_overrides, recipient_overrides) = self.get_overrides();
        let connection_overrides: &ConfigOverrides =
            self.conn.connection_overrides.get_or_insert_with(|| {
                get_connection_overrides(self.conn.ip, &self.session_config.config)
            });

        let recipients = &self.message.as_ref().unwrap().recipients;
        let recipient_overrides: ConfigOverrides =
            get_recipient_overrides(recipients, &self.session_config.config);

        let signer = Signer::init(
            &self.session_config.config,
            headers,
            sender,
            matches,
            &connection_overrides.signing_config,
            &recipient_overrides.signing_config,
        )?;

        Ok(Mode::Signing(signer))
    }

    async fn enter_verifying_mode(
        &mut self,
        id: &str,
        headers: HeaderFields,
    ) -> Mode {
        debug!("{id}: entered verifying mode");

        // TODO duplicated
        let connection_overrides: &ConfigOverrides =
            self.conn.connection_overrides.get_or_insert_with(|| {
                get_connection_overrides(self.conn.ip, &self.session_config.config)
            });
        // TODO delete `.clone()` once repaired version of viadkim published
        let recipients = &self.message.as_ref().unwrap().recipients.clone();
        let recipient_overrides: ConfigOverrides =
            get_recipient_overrides(recipients, &self.session_config.config);

        let verifier = Verifier::init(&self.session_config, headers,
            &connection_overrides.verification_config,
            &recipient_overrides.verification_config,
        ).await;

        Mode::Verifying(verifier)
    }

    pub fn process_body_chunk(&mut self, chunk: &[u8]) -> Result<Status, Box<dyn Error>> {
        let message = match self.message.as_mut() {
            Some(message) => message,
            None => return Err("message context not available".into()),
        };

        match &mut message.mode {
            Mode::Inactive => Ok(Status::Skip),  // not reached
            Mode::Signing(signer) => signer.process_body_chunk(chunk),
            Mode::Verifying(verifier) => verifier.process_body_chunk(chunk),
        }
    }

    pub async fn finish_message(
        &mut self,
        id: &str,
        reply: &mut impl SetErrorReply,
        actions: &impl ContextActions,
    ) -> Result<Status, Box<dyn Error>> {
        let message = match self.message.take() {
            Some(message) => message,
            None => return Err("message context not available".into()),
        };

        let config = &self.session_config.config;

        if config.delete_incoming_authentication_results {
            delete_auth_results_headers(actions, config, id, message.auth_results_deletions)
                .await?;
        }

        match message.mode {
            Mode::Inactive => Ok(Status::Continue),  // not reached
            Mode::Signing(signer) => {
                let status = signer.finish(id, config, actions).await?;

                Ok(status)
            }
            Mode::Verifying(verifier) => {
                let authserv_id = authserv_id(config, self.conn.hostname());

                let status = verifier.finish(
                    id, config, authserv_id, message.from_addresses.as_ref(), reply, actions
                ).await?;

                Ok(status)
            }
        }
    }

    pub fn abort_message(&mut self) {
        self.message = None;
    }
}

// TODO copied from SPF Milter
fn eq_authserv_ids(id1: &str, id2: &str) -> bool {
    fn to_unicode(s: &str) -> String {
        let (result, e) = idna::domain_to_unicode(s);
        if e.is_err() {
            debug!("validation error while converting domain \"{s}\" to Unicode");
        }
        result
    }

    to_unicode(id1) == to_unicode(id2)
}

fn is_trusted_sender(id: &str, config: &Config, ip: Option<IpAddr>, authenticated: bool) -> bool {
    match ip {
        Some(addr) => {
            if config.trusted_networks.contains(addr) {
                if addr.is_loopback() {
                    debug!("{id}: message from trusted source: local connection");
                } else {
                    debug!("{id}: message from trusted source: connection from trusted network address {addr}");
                }
                return true;
            }
        }
        None => {
            // Like OpenDKIM, treat no IP as local connection.
            if config.trusted_networks.contains_loopback() {
                debug!("{id}: message from trusted source: no IP address, presumed local connection");
                return true;
            }
        }
    }

    if config.trust_authenticated_senders && authenticated {
        debug!("{id}: message from trusted source: authenticated sender");
        return true;
    }

    false
}

// See RFC 5322, section 3.6.2 for details on the relationship of the Sender and
// From header.
//
// Also note RFC 6376, appendix B.2.3: ‘A common practice among systems that are
// primarily redistributors of mail is to add a Sender header field to the
// message to identify the address being used to sign the message.’
fn extract_sender<'a>(
    id: &str,
    sender_address: Option<&'a Result<MailAddr, SenderAddrError>>,
    from_addresses: Option<&'a Result<Vec<MailAddr>, SenderAddrError>>,
) -> Option<&'a MailAddr> {
    match sender_address {
        Some(Ok(addr)) => {
            debug!("{id}: using originator in Sender header: {addr}");
            return Some(addr);
        }
        Some(Err(_)) => {
            // TODO perhaps a broken or repeated Sender header should not fall back to From
            debug!("{id}: originator address in Sender header not usable, falling back to From");
        }
        None => {}
    }

    match from_addresses {
        Some(Ok(from_addresses)) => {
            if from_addresses.len() > 1 {
                debug!("{id}: originator address in From header not usable");
                None
            } else {
                let addr = from_addresses.first().unwrap();
                debug!("{id}: using originator in From header: {addr}");
                Some(addr)
            }
        }
        Some(Err(_)) => {
            debug!("{id}: originator address in From header not usable");
            None
        }
        None => {
            debug!("{id}: no originator address in From or Sender header");
            None
        }
    }
}

pub fn authserv_id<'a>(config: &'a Config, hostname: &'a str) -> &'a str {
    config.authserv_id.as_deref().unwrap_or(hostname)
}

#[derive(Clone, Debug)]
pub enum DomainExpr {
    Domain(DomainName),
    SenderDomain,  // .
    Identity(IdentityExpr),
}

#[derive(Clone, Debug)]
pub struct IdentityExpr {
    pub local_part: Option<LocalPartExpr>,
    pub domain_part: IdentityDomainExpr,
}

#[derive(Clone, Debug)]
pub enum LocalPartExpr {
    LocalPart(String),
    SenderLocalPart,  // .
}

#[derive(Clone, Debug)]
pub enum IdentityDomainExpr {
    Domain(DomainName),
    SenderDomain,  // .
    SplitDomain(Selector, DomainName),
}

// TODO move elsewhere
#[derive(Clone, Debug)]
pub struct SenderMatch {
    pub domain: DomainExpr,
    pub selector: Selector,
    pub key: Arc<SigningKey>,
    pub signing_config: Option<PartialSigningConfig>,
}

fn find_matching_senders(
    signing_senders: &SigningSenders,
    sender: &MailAddr,
) -> Vec<SenderMatch> {
    let MailAddr { local_part, domain } = sender;

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

fn get_connection_overrides(ip: Option<IpAddr>, config: &Config) -> ConfigOverrides {
    let mut result = ConfigOverrides::default();

    if let Some(connection_overrides) = &config.connection_overrides {
        if let Some(ip) = ip {
            for entry in connection_overrides {
                if entry.net.contains(&ip) {
                    result.merge(&entry.config);
                }
            }
        }
    }

    result
}

fn get_recipient_overrides(recipients: &[String], config: &Config) -> ConfigOverrides {
    let mut result = ConfigOverrides::default();

    if let Some(recipient_overrides) = &config.recipient_overrides {
        for recipient in recipients {
            // TODO ensure is parsable as email addr
            for overrides in &recipient_overrides.entries {
                if overrides.expr.is_match(recipient) {
                    result.merge(&overrides.config);
                }
            }
        }
    }

    result
}

async fn delete_auth_results_headers(
    actions: &impl ContextActions,
    config: &Config,
    id: &str,
    deletions: Vec<usize>,
) -> Result<(), ActionError> {
    // Delete headers in reverse: each deletion shifts the header indices after
    // it, so only reverse iteration selects the correct headers.
    for i in deletions.into_iter().rev() {
        if config.dry_run {
            debug!(
                "{id}: deleting incoming Authentication-Results header instance {i} [dry run, not done]",
            );
        } else {
            debug!("{id}: deleting incoming Authentication-Results header instance {i}");
            actions
                .change_header("Authentication-Results", i as _, None::<CString>)
                .await?;
        }
    }

    Ok(())
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

        let from_address = MailAddr::new("itsame@mail.example.com").unwrap();

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
