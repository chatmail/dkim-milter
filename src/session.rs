// DKIM Milter – milter for DKIM signing and verification
// Copyright © 2022–2023 David Bürgin <dbuergin@gluet.ch>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    auth_results,
    config::{
        self,
        model::{ConfigOverrides, OpMode},
        Config, SessionConfig,
    },
    datastore::{self, SenderMatch},
    format::{self, AddrSpec, MailAddr},
    sign::Signer,
    util,
    verify::Verifier,
};
use indymilter::{ActionError, ContextActions, SetErrorReply, Status};
use log::{debug, error, warn};
use std::{
    borrow::Cow,
    error::Error,
    ffi::CString,
    fmt::{self, Display, Formatter},
    mem,
    net::IpAddr,
    sync::Arc,
};
use viadkim::{
    header::{FieldBody, FieldName, HeaderField, HeaderFields},
    signature::DomainName,
};

#[derive(Default)]
enum Mode {
    #[default]
    Inactive,
    Signing(Signer),
    Verifying(Verifier),
}

enum SenderAddrError {
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
    env_sender: Option<String>,
    env_recipients: Vec<String>,
    header_bytes: usize,
    sender_address: Option<Result<AddrSpec, SenderAddrError>>,
    from_addresses: Option<Result<Vec<AddrSpec>, SenderAddrError>>,
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

// Implementation note: Careful when returning `Status::Accept` instead of
// `Status::Continue`: it ends the processing flow for the message, bypassing
// any later steps such as header deletion.

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

    pub fn set_envelope_sender(&mut self, env_sender: String) {
        let sender = trim_env_address(env_sender);
        self.message.as_mut().unwrap().env_sender = Some(sender);
    }

    pub fn set_authenticated(&mut self) {
        self.message.as_mut().unwrap().auth = true;
    }

    pub fn add_envelope_recipient(&mut self, env_recipient: String) {
        let rcpt = trim_env_address(env_recipient);
        self.message.as_mut().unwrap().env_recipients.push(rcpt);
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
        let value = util::normalize_to_crlf(&value);

        // Count and limit amount of header data that can be accumulated
        // (compare OpenDKIM max size 64*1024).
        const MAX_HEADER_LEN: usize = 256 * 1024;

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
                    Err(_) => {
                        debug!("{id}: unusable Sender header field");
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
                    Err(_) => {
                        debug!("{id}: unusable From header field");
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
                if eq_authserv_ids(id, aid, &incoming_aid) {
                    debug!(
                        "{id}: recognized own authserv-id in incoming Authentication-Results header instance {}",
                        message.auth_results_i
                    );
                    message.auth_results_deletions.push(message.auth_results_i);
                }
            } else {
                debug!(
                    "{id}: could not parse incoming Authentication-Results header instance {}",
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

    // This step ends the header processing bit, and so will freely remove
    // certain things from the message-scoped data *that is not used further
    // down*.
    pub async fn init_processing(
        &mut self,
        id: &str,
    ) -> Result<Status, Box<dyn Error + Send + Sync>> {
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
                return Ok(Status::Continue);
            }
        };

        let sender_address = message.sender_address.take();
        let from_addresses = message.from_addresses.take();

        let config = &self.session_config.config;

        // RFC 6376, section 3.8: ‘Signers and Verifiers SHOULD take reasonable
        // steps to ensure that the messages they are processing are valid
        // according to [RFC5322], [RFC2045], and any other relevant message
        // format standards.’ For now simply log that we are proceeding with an
        // ill-formed header.
        if let Err(e) = validate_rfc5322(&headers, sender_address.as_ref(), from_addresses.as_ref()) {
            debug!("{id}: proceeding with header not conforming to RFC 5322: {e}");
        }

        // A trusted sender is eligible for signing, and is not eligible for
        // verifying.
        let authorized = is_trusted_sender(id, config, self.conn.ip, message.auth);

        match (config.mode, authorized) {
            (OpMode::Sign | OpMode::Auto, Auth::Trusted) => {
                let sender = match extract_sender(id, sender_address, from_addresses) {
                    Some(sender) => sender,
                    None => {
                        debug!("{id}: not signing message from trusted sender without usable originator");
                        return Ok(Status::Continue);
                    }
                };

                let match_result = match (
                    config.signing_senders.as_deref(),
                    config.signing_keys.as_deref(),
                ) {
                    (Some(senders), Some(keys)) => {
                        datastore::find_matching_senders(senders, keys, &sender).await
                    }
                    _ => {
                        debug!("{id}: not signing message, no signing senders or keys available");
                        return Ok(Status::Continue);
                    }
                };

                let matches = match match_result {
                    Ok(matches) => matches,
                    Err(e) => {
                        // Log at error level: Failure to provide service due to
                        // configuration lookup error (ie, a user error!).
                        config::log_errors(Some(id), e.as_ref());
                        error!("{id}: failed to look up signing senders or keys, aborting message transaction");
                        return Ok(Status::Tempfail);
                    }
                };

                if matches.is_empty() {
                    debug!("{id}: not signing message from trusted sender not configured for signing");
                    return Ok(Status::Continue);
                }

                if config.require_envelope_sender_match
                    && !is_env_sender_match(message.env_sender.as_deref(), &sender)
                {
                    // Log at warn level because here a trusted sender for whom
                    // signing was set up is using a different originator
                    // header. If this is not a malicious attempt, then it is
                    // likely a misconfiguration.
                    warn!("{id}: not signing message, trusted sender used originator header \
                        that did not match envelope sender");
                    return Ok(Status::Continue);
                }

                self.enter_signing_mode(id, headers, sender, matches).await
            }
            (OpMode::Verify | OpMode::Auto, Auth::Untrusted) => {
                let from_addresses = match from_addresses {
                    Some(Ok(addrs)) => addrs.into_iter()
                        .filter_map(|addr| addr.into_mail_addr())
                        .collect(),
                    _ => vec![],
                };

                let status = self.enter_verifying_mode(id, headers, from_addresses).await;

                Ok(status)
            }
            (OpMode::Sign, Auth::Untrusted) => {
                debug!("{id}: not signing message from untrusted sender");
                Ok(Status::Continue)
            }
            (OpMode::Verify, Auth::Trusted) => {
                debug!("{id}: not verifying message from trusted sender");
                Ok(Status::Continue)
            }
        }
    }

    async fn enter_signing_mode(
        &mut self,
        id: &str,
        headers: HeaderFields,
        sender: MailAddr,
        matches: Vec<SenderMatch>,
    ) -> Result<Status, Box<dyn Error + Send + Sync>> {
        debug!("{id}: entered signing mode");

        let config = &self.session_config.config;

        let connection_overrides = match get_connection_overrides(self.conn.ip, config).await {
            Ok(o) => o,
            Err(e) => {
                config::log_errors(Some(id), e.as_ref());
                error!("{id}: failed to look up connection overrides, aborting message transaction");
                return Ok(Status::Tempfail);
            }
        };

        let message = self.message.as_mut().unwrap();

        let recipients = mem::take(&mut message.env_recipients);

        let recipient_overrides = match get_recipient_overrides(recipients, config).await {
            Ok(o) => o,
            Err(e) => {
                config::log_errors(Some(id), e.as_ref());
                error!("{id}: failed to look up recipient overrides, aborting message transaction");
                return Ok(Status::Tempfail);
            }
        };

        let signer = Signer::init(
            id,
            config,
            headers,
            &sender,
            matches,
            &connection_overrides.signing_config,
            &recipient_overrides.signing_config,
        )?;

        message.mode = Mode::Signing(signer);

        Ok(Status::Continue)
    }

    async fn enter_verifying_mode(
        &mut self,
        id: &str,
        headers: HeaderFields,
        from_addresses: Vec<MailAddr>,
    ) -> Status {
        debug!("{id}: entered verifying mode");

        let config = &self.session_config.config;

        let connection_overrides = match get_connection_overrides(self.conn.ip, config).await {
            Ok(o) => o,
            Err(e) => {
                config::log_errors(Some(id), e.as_ref());
                error!("{id}: failed to look up connection overrides, aborting message transaction");
                return Status::Tempfail;
            }
        };

        let message = self.message.as_mut().unwrap();

        let recipients = mem::take(&mut message.env_recipients);

        let recipient_overrides = match get_recipient_overrides(recipients, config).await {
            Ok(o) => o,
            Err(e) => {
                config::log_errors(Some(id), e.as_ref());
                error!("{id}: failed to look up recipient overrides, aborting message transaction");
                return Status::Tempfail;
            }
        };

        let verifier = Verifier::init(
            &self.session_config,
            headers,
            from_addresses,
            &connection_overrides.verification_config,
            &recipient_overrides.verification_config,
        )
        .await;

        message.mode = Mode::Verifying(verifier);

        Status::Continue
    }

    pub fn process_body_chunk(&mut self, chunk: &[u8]) -> Result<Status, Box<dyn Error>> {
        let message = match self.message.as_mut() {
            Some(message) => message,
            None => return Err("message context not available".into()),
        };

        match &mut message.mode {
            Mode::Inactive => Ok(Status::Skip),
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

        // Like OpenDKIM, delete Authentication-Results headers only when
        // verifying, ie when we are about to add our own such header.
        if config.delete_incoming_authentication_results {
            match &message.mode {
                Mode::Verifying(_) => {
                    delete_auth_results_headers(actions, config, id, message.auth_results_deletions)
                        .await?;
                }
                _ if !message.auth_results_deletions.is_empty() => {
                    debug!("{id}: not deleting Authentication-Results headers when not in verifying mode");
                }
                _ => {}
            }
        }

        match message.mode {
            Mode::Inactive => Ok(Status::Continue),
            Mode::Signing(signer) => {
                let status = signer.finish(id, config, actions).await?;

                Ok(status)
            }
            Mode::Verifying(verifier) => {
                let authserv_id = authserv_id(config, self.conn.hostname());

                let status = verifier.finish(id, config, authserv_id, reply, actions).await?;

                Ok(status)
            }
        }
    }

    pub fn abort_message(&mut self) {
        self.message = None;
    }
}

fn trim_env_address(env_addr: String) -> String {
    match env_addr.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
        Some(s) => s.into(),
        None => env_addr,
    }
}

// Copied from SPF Milter, consolidate later.
fn eq_authserv_ids(id: &str, aid1: &str, aid2: &str) -> bool {
    let to_unicode = |s| {
        let (result, e) = idna::domain_to_unicode(s);
        if e.is_err() {
            debug!("{id}: validation error while converting domain \"{s}\" to Unicode");
        }
        result
    };

    to_unicode(aid1) == to_unicode(aid2)
}

// The header validation utility here allows partial checking for RFC 5322
// conformance; see DKIM §3.8: ‘Signers and Verifiers SHOULD take reasonable
// steps to ensure that the messages they are processing are valid according to
// RFC5322, RFC2045, and any other relevant message format standards.’

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum HeaderValidationError {
    NoSingleDate,
    NoSingleFrom,
    MultipleSender,
    MultipleReplyTo,
    MultipleTo,
    MultipleCc,
    MultipleBcc,
    MultipleMessageId,
    MultipleInReplyTo,
    MultipleReferences,
    MultipleSubject,
    MultiMailboxFromNoSender,
}

impl Display for HeaderValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSingleDate => write!(f, "not exactly one Date header"),
            Self::NoSingleFrom => write!(f, "not exactly one From header"),
            Self::MultipleSender => write!(f, "more than one Sender header"),
            Self::MultipleReplyTo => write!(f, "more than one Reply-To header"),
            Self::MultipleTo => write!(f, "more than one To header"),
            Self::MultipleCc => write!(f, "more than one Cc header"),
            Self::MultipleBcc => write!(f, "more than one Bcc header"),
            Self::MultipleMessageId => write!(f, "more than one Message-ID header"),
            Self::MultipleInReplyTo => write!(f, "more than one In-Reply-To header"),
            Self::MultipleReferences => write!(f, "more than one References header"),
            Self::MultipleSubject => write!(f, "more than one Subject header"),
            Self::MultiMailboxFromNoSender => {
                write!(f, "multiple mailboxes in From but no Sender header")
            }
        }
    }
}

impl Error for HeaderValidationError {}

// Validates the given header according to RFC 5322, 3.6. This only validates
// the cardinality requirements in the table at the end of section 3.6, not the
// format of the headers.
fn validate_rfc5322(
    header: impl AsRef<[HeaderField]>,
    sender_address: Option<&Result<AddrSpec, SenderAddrError>>,
    from_addresses: Option<&Result<Vec<AddrSpec>, SenderAddrError>>,
) -> Result<(), HeaderValidationError> {
    fn count_names(header: &[HeaderField], name: &str) -> usize {
        header.iter().filter(|(n, _)| *n == name).count()
    }

    let header = header.as_ref();

    if count_names(header, "Date") != 1 {
        return Err(HeaderValidationError::NoSingleDate);
    }
    if count_names(header, "From") != 1 {
        return Err(HeaderValidationError::NoSingleFrom);
    }
    if count_names(header, "Sender") > 1 {
        return Err(HeaderValidationError::MultipleSender);
    }
    if count_names(header, "Reply-To") > 1 {
        return Err(HeaderValidationError::MultipleReplyTo);
    }
    if count_names(header, "To") > 1 {
        return Err(HeaderValidationError::MultipleTo);
    }
    if count_names(header, "Cc") > 1 {
        return Err(HeaderValidationError::MultipleCc);
    }
    if count_names(header, "Bcc") > 1 {
        return Err(HeaderValidationError::MultipleBcc);
    }
    if count_names(header, "Message-ID") > 1 {
        return Err(HeaderValidationError::MultipleMessageId);
    }
    if count_names(header, "In-Reply-To") > 1 {
        return Err(HeaderValidationError::MultipleInReplyTo);
    }
    if count_names(header, "References") > 1 {
        return Err(HeaderValidationError::MultipleReferences);
    }
    if count_names(header, "Subject") > 1 {
        return Err(HeaderValidationError::MultipleSubject);
    }

    // RFC 5322, section 3.6.2: ‘If the from field contains more than one
    // mailbox specification in the mailbox-list, then the sender field […] MUST
    // appear in the message.’ Again, this only checks cardinality, not if these
    // headers are well-formed.
    if let Some(Ok(addrs)) = from_addresses {
        if addrs.len() > 1 && sender_address.is_none() {
            return Err(HeaderValidationError::MultiMailboxFromNoSender);
        }
    }

    Ok(())
}

enum Auth {
    Trusted,
    Untrusted,
}

fn is_trusted_sender(id: &str, config: &Config, ip: Option<IpAddr>, authenticated: bool) -> Auth {
    match ip {
        Some(addr) => {
            if config.trusted_networks.contains(addr) {
                if addr.is_loopback() {
                    debug!("{id}: message from trusted source: local connection");
                } else {
                    debug!("{id}: message from trusted source: connection from trusted network address {addr}");
                }
                return Auth::Trusted;
            }
        }
        None => {
            // Like OpenDKIM, treat no IP as local connection.
            if config.trusted_networks.contains_loopback() {
                debug!("{id}: message from trusted source: no IP address, presumed local connection");
                return Auth::Trusted;
            }
        }
    }

    if config.trust_authenticated_senders && authenticated {
        debug!("{id}: message from trusted source: authenticated sender");
        return Auth::Trusted;
    }

    Auth::Untrusted
}

// See RFC 5322, section 3.6.2 for details on the relationship of the Sender and
// From header.
//
// Also note RFC 6376, appendix B.2.3: ‘A common practice among systems that are
// primarily redistributors of mail is to add a Sender header field to the
// message to identify the address being used to sign the message.’
fn extract_sender(
    id: &str,
    sender_address: Option<Result<AddrSpec, SenderAddrError>>,
    from_addresses: Option<Result<Vec<AddrSpec>, SenderAddrError>>,
) -> Option<MailAddr> {
    match sender_address {
        Some(Ok(addr)) => {
            match addr.into_mail_addr() {
                Some(addr) => {
                    debug!("{id}: using originator in Sender header: {addr}");
                    return Some(addr);
                }
                None => {
                    debug!("{id}: originator address in Sender header is literal, falling back to From");
                }
            }
        }
        Some(Err(_)) => {
            // In case the Sender header is broken or repeated, give up.
            debug!("{id}: originator address in Sender header not usable");
            return None;
        }
        None => {}
    }

    match from_addresses {
        Some(Ok(from_addresses)) => {
            assert!(!from_addresses.is_empty());
            let from_addresses: Vec<_> = from_addresses.into_iter()
                .filter_map(|addr| addr.into_mail_addr())
                .collect();
            match from_addresses.len() {
                0 => {
                    debug!("{id}: literal originator addresses in From header not usable");
                }
                1 => {
                    let addr = from_addresses.into_iter().next().unwrap();
                    debug!("{id}: using originator in From header: {addr}");
                    return Some(addr);
                }
                _ => {
                    debug!("{id}: multiple originator addresses in From header not usable");
                }
            }
        }
        Some(Err(_)) => {
            debug!("{id}: originator address in From header not usable");
        }
        None => {
            debug!("{id}: no originator address in From or Sender header");
        }
    }

    None
}

fn is_env_sender_match(env_sender: Option<&str>, sender: &MailAddr) -> bool {
    // no or empty (<>) envelope sender, accept
    let env_sender = match env_sender.filter(|s| !s.is_empty()) {
        Some(env_sender) => env_sender,
        None => return true,
    };

    // Try to compare the strings directly.
    if env_sender.eq_ignore_ascii_case(&sender.to_string()) {
        return true;
    }

    // Else, try comparing after IDNA/case-normalise.

    let MailAddr { local_part, domain } = sender;
    let sender = format!("{local_part}@{}", domain.to_ascii());

    if let Some(env_sender) = env_sender.rsplit_once('@').and_then(|(l, d)| {
        let domain = DomainName::new(d).ok()?.to_ascii();
        Some(format!("{l}@{domain}"))
    }) {
        env_sender.eq_ignore_ascii_case(&sender)
    } else {
        false
    }
}

pub fn authserv_id<'a>(config: &'a Config, hostname: &'a str) -> &'a str {
    config.authserv_id.as_deref().unwrap_or(hostname)
}

async fn get_connection_overrides(
    ip: Option<IpAddr>,
    config: &Config,
) -> Result<ConfigOverrides, Box<dyn Error + Send + Sync>> {
    let mut result = ConfigOverrides::default();

    if let Some(connection_overrides) = &config.connection_overrides {
        if let Some(ip) = ip {
            let entries = connection_overrides.find_all(ip).await?;

            // While all applicable overrides have been retrieved, only apply
            // the first one for now.
            if let Some(entry) = entries.into_iter().next() {
                result.merge(&entry);
            }
        }
    }

    Ok(result)
}

async fn get_recipient_overrides(
    recipients: Vec<String>,
    config: &Config,
) -> Result<ConfigOverrides, Box<dyn Error + Send + Sync>> {
    let mut result = ConfigOverrides::default();

    if let Some(recipient_overrides) = &config.recipient_overrides {
        let entries = recipient_overrides.find_all(recipients).await?;

        // While all applicable overrides have been retrieved, only apply the
        // first one for now.
        if let Some(entry) = entries.into_iter().next() {
            result.merge(&entry);
        }
    }

    Ok(result)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rfc5322_ok() {
        let mut header = vec![
            (
                FieldName::new("Date").unwrap(),
                FieldBody::new(*b" Mon, 22 May 2023 11:59:28 +0200").unwrap(),
            ),
            (
                FieldName::new("From").unwrap(),
                FieldBody::new(*b" me").unwrap(),
            ),
            (
                FieldName::new("To").unwrap(),
                FieldBody::new(*b" you").unwrap(),
            ),
        ];

        assert_eq!(validate_rfc5322(&header, None, None), Ok(()));

        header.push((
            FieldName::new("fRom").unwrap(),
            FieldBody::new(*b" me too").unwrap(),
        ));

        assert_eq!(
            validate_rfc5322(&header, None, None),
            Err(HeaderValidationError::NoSingleFrom)
        );
    }
}
