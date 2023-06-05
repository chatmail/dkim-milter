use crate::{
    config::{
        model::{OperationMode, PartialSigningConfig, SigningSenders},
        Config, RuntimeConfig,
    },
    format::{self, EmailAddr},
    sign::Signer,
    verify::Verifier,
};
use bstr::ByteSlice;
use indymilter::{ContextActions, Status};
use log::{debug, info};
use std::{borrow::Cow, error::Error, mem, net::IpAddr, sync::Arc};
use viadkim::{
    header::{self, FieldBody, FieldName, HeaderFields},
    signature::{DomainName, Selector},
    SigningKey,
};

#[derive(Default)]
enum Mode {
    #[default]
    Inactive,
    Signing(Signer),
    Verifying(Verifier),
}

pub enum FromAddrError {
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

    fn hostname(&self) -> &str {
        self.hostname.as_deref().expect("no hostname available")
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
        message.header_bytes = message
            .header_bytes
            .saturating_add(name.len() + value.len() + 3);
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
                        debug!("{id}: unusable Sender header field: {e}");
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
                        debug!("{id}: unusable From header field: {e}");
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
            Err(_) => {
                // For now, give up if inputs don't look like an email header at all
                debug!("{id}: accepted message with unusable header fields");
                return Ok(Status::Accept);
            }
        };

        if let Err(e) = header::validate_rfc5322(&headers) {
            // For now, simply log that we are proceeding with an ill-formed header.
            info!("{id}: proceeding with header not conforming to RFC 5322: {e}");
        }

        // A trusted sender is eligible for signing, and is not eligible for
        // verifying.
        let authorized = is_trusted_sender(id, &self.runtime.config, self.conn.ip, message.auth);

        let mode = match self.runtime.config.mode {
            mode @ (OperationMode::Sign | OperationMode::Auto) => {
                if authorized {
                    let sender = extract_sender(
                        id,
                        message.sender_address.as_ref(),
                        message.from_addresses.as_ref(),
                    );

                    let matches = match sender {
                        Some(sender) => find_matching_senders(&self.runtime.config.signing_senders, sender),
                        None => vec![],
                    };

                    // signing mode if authorised and right domain to sign in From
                    if matches.is_empty() {
                        debug!("{id}: accepted message from sender not configured for signing");
                        return Ok(Status::Accept);
                    } else {
                        debug!("{id}: entered signing mode");

                        let recipients = &self.message.as_ref().unwrap().recipients;

                        let signer = Signer::init(&self.runtime, recipients, headers, matches)?;

                        Mode::Signing(signer)
                    }
                } else if mode == OperationMode::Auto {
                    debug!("{id}: entered verifying mode");

                    let verifier = Verifier::init(&self.runtime, headers).await;

                    Mode::Verifying(verifier)
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
                    debug!("{id}: entered verifying mode");

                    let verifier = Verifier::init(&self.runtime, headers).await;

                    Mode::Verifying(verifier)
                }
            }
        };

        let message = self.message.as_mut().unwrap();
        message.mode = mode;

        Ok(Status::Continue)
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
        actions: &impl ContextActions,
    ) -> Result<Status, Box<dyn Error>> {
        let message = match self.message.take() {
            Some(message) => message,
            None => return Err("message context not available".into()),
        };

        match message.mode {
            Mode::Inactive => Ok(Status::Continue),  // not reached
            Mode::Signing(signer) => {
                let status = signer.finish(id, actions).await?;

                Ok(status)
            }
            Mode::Verifying(verifier) => {
                let authserv_id = authserv_id(&self.runtime.config, self.conn.hostname());

                let status = verifier.finish(id, authserv_id, actions).await?;

                Ok(status)
            }
        }
    }
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
fn extract_sender<'a>(
    id: &str,
    sender_address: Option<&'a Result<EmailAddr, FromAddrError>>,
    from_addresses: Option<&'a Result<Vec<EmailAddr>, FromAddrError>>,
) -> Option<&'a EmailAddr> {
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
pub struct SenderMatch {
    pub domain: DomainName,
    pub selector: Selector,
    pub key: Arc<SigningKey>,
    pub signing_config: Option<PartialSigningConfig>,
}

fn find_matching_senders(
    signing_senders: &SigningSenders,
    sender: &EmailAddr,
) -> Vec<SenderMatch> {
    let EmailAddr { local_part, domain } = sender;

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
