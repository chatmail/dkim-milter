use crate::{
    config::{
        model::{
            Expiration, OverrideEntries, OverrideNetworkEntry, OversignedHeaders,
            PartialSigningConfig, SignedFieldName, SignedHeaders, SigningConfig,
        },
        Config,
    },
    session::SenderMatch,
};
use indymilter::{ActionError, ContextActions, Status};
use log::{error, info};
use std::{collections::HashSet, error::Error, net::IpAddr, sync::Arc};
use viadkim::{
    crypto::SigningKey,
    header::{FieldName, HeaderFields},
    message_hash::BodyHasherStance,
    signature::{DomainName, Selector, SigningAlgorithm},
    signer::{self, BodyLength, HeaderSelection, SignRequest, SigningResult},
};

pub struct Signer {
    delegate: viadkim::Signer<Arc<SigningKey>>,
}

impl Signer {
    pub fn init(
        config: &Config,
        ip: Option<IpAddr>,
        recipients: &[String],
        headers: HeaderFields,
        matches: Vec<SenderMatch>,
    ) -> Result<Self, Box<dyn Error>> {
        assert!(!matches.is_empty());

        // TODO

        let connection_overrides = config
            .connection_overrides
            .as_ref()
            .and_then(|overrides| find_matching_connection_overrides(overrides, ip));

        let recipient_overrides = config
            .recipient_overrides
            .as_ref()
            .and_then(|overrides| find_matching_recipient_overrides(overrides, recipients));

        let base_overrides_config = match (connection_overrides, recipient_overrides) {
            (Some(o1), Some(o2)) => Some(o1.combine_with(&o2)),
            (Some(o), None) | (None, Some(o)) => Some(o),
            (None, None) => None,
        };

        // step through matches and create SignRequest for each match

        let mut requests = vec![];
        for match_ in matches {
            let domain = match_.domain;
            let selector = match_.selector;
            let signing_key = match_.key;

            let signing_config = match (&match_.signing_config, &base_overrides_config) {
                (Some(c1), Some(c2)) => {
                    // TODO shouldn't c1 override c2?
                    let combined = c1.combine_with(c2);
                    config.signing_config.combine_with(&combined)
                }
                (Some(c), None) | (None, Some(c)) => config.signing_config.combine_with(c),
                (None, None) => Ok(config.signing_config.clone()),
            };

            let signing_config = match signing_config {
                Ok(config) => config,
                Err(e) => {
                    error!("failed to construct valid signing configuration, ignoring request: {e}");
                    continue;
                }
            };

            match make_sign_request(&signing_config, &headers, domain, selector, signing_key) {
                Ok(request) => {
                    requests.push(request);
                }
                Err(e) => {
                    error!("failed to create sign request, ignoring request: {e}");
                }
            }
        }

        let signer = viadkim::Signer::prepare_signing(headers, requests)
            .map_err(|_| "could not prepare signing")?;

        Ok(Self { delegate: signer })
    }

    pub fn process_body_chunk(&mut self, chunk: &[u8]) -> Result<Status, Box<dyn Error>> {
        let status = self.delegate.process_body_chunk(chunk);

        Ok(if let BodyHasherStance::Done = status {
            Status::Skip
        } else {
            Status::Continue
        })
    }

    pub async fn finish(
        self,
        id: &str,
        config: &Config,
        actions: &impl ContextActions,
    ) -> Result<Status, ActionError> {
        let sigs = self.delegate.sign().await;

        for res in sigs {
            match res {
                Err(_e) => {
                    // TODO state domain/selector
                    error!("{id}: failed to sign message");
                }
                Ok(SigningResult {
                    signature,
                    header_name: name,
                    header_value: value,
                }) => {
                    if config.dry_run {
                        info!("{id}: signed message for {} [dry run, not done]", signature.domain);
                    } else {
                        info!("{id}: signed message for {}", signature.domain);

                        // convert SMTP CRLF to milter line endings
                        let value = value.replace("\r\n", "\n");

                        actions.insert_header(0, name, value).await?;
                    }
                }
            }
        }

        Ok(Status::Continue)
    }
}

fn find_matching_connection_overrides(
    connection_overrides: &[OverrideNetworkEntry],
    ip: Option<IpAddr>,
) -> Option<PartialSigningConfig> {
    if let Some(ip) = ip {
        for entry in connection_overrides {
            if entry.net.contains(&ip) {
                return Some(entry.config.signing_config.clone());
            }
        }
    }
    None
}

fn find_matching_recipient_overrides(
    recipient_overrides: &OverrideEntries,
    recipients: &[String],
    // from_address: &EmailAddr,
) -> Option<PartialSigningConfig> {
    for recipient in recipients {
        // TODO ensure is parsable as email addr
        for overrides in &recipient_overrides.entries {
            if overrides.expr.is_match(recipient) {
                return Some(overrides.config.signing_config.clone());
            }
        }
    }
    None
}

fn make_sign_request(
    config: &SigningConfig,
    headers: &HeaderFields,
    domain: DomainName,
    selector: Selector,
    signing_key: Arc<SigningKey>,
) -> Result<SignRequest<Arc<SigningKey>>, Box<dyn Error>> {
    let key_type = signing_key.key_type();

    let hash_algorithm = config.hash_algorithm;
    let alg = SigningAlgorithm::from_parts(key_type, hash_algorithm)
        .ok_or("invalid key type/hash algorithm pair")?;

    let mut request = SignRequest::new(domain, selector, alg, signing_key);

    request.canonicalization = config.canonicalization;

    request.valid_duration = match config.expire_after {
        Expiration::Never => None,
        Expiration::After(duration) => Some(duration),
    };

    request.copy_headers = config.copy_headers;

    if config.limit_body_length {
        request.body_length = BodyLength::MessageContent;
    }

    request.header_selection = HeaderSelection::Manual(select_headers(
        headers,
        &config.signed_headers,
        &config.oversigned_headers,
        &config.default_signed_headers,
        &config.default_unsigned_headers,
    ));

    if config.request_reports {
        request.ext_tags.push(("r".into(), "y".into()));
    }

    Ok(request)
}

fn select_headers(
    headers: &HeaderFields,
    signed_headers: &SignedHeaders,
    oversigned_headers: &OversignedHeaders,
    default_signed_headers: &[SignedFieldName],
    default_unsigned_headers: &[SignedFieldName],
) -> Vec<FieldName> {
    let mut selection: Vec<FieldName> = match signed_headers {
        s @ (SignedHeaders::Pick(names) | SignedHeaders::PickWithDefault(names)) => {
            let mut names_to_pick: HashSet<_> = names.iter().map(|n| n.as_ref()).collect();
            if matches!(s, SignedHeaders::PickWithDefault(_)) {
                names_to_pick.extend(default_signed_headers.iter().map(|n| n.as_ref()));
            }
            signer::select_headers(headers, move |name| names_to_pick.contains(name))
                .cloned()
                .collect()
        }
        SignedHeaders::All => {
            let names_not_to_pick: HashSet<_> = default_unsigned_headers
                .iter()
                .map(|n| n.as_ref())
                .collect();
            signer::select_headers(headers, move |name| !names_not_to_pick.contains(name))
                .cloned()
                .collect()
        }
    };

    match oversigned_headers {
        OversignedHeaders::Pick(names) => {
            let to_oversign: HashSet<_> = names.iter().map(|n| n.as_ref()).collect();

            let mut seen: HashSet<&FieldName> = HashSet::new();
            let oversign: Vec<_> = selection
                .iter()
                .filter(|name| to_oversign.contains(name) && seen.insert(name))
                .cloned()
                .collect();

            selection.extend(oversign);
        }
        OversignedHeaders::Signed => {
            let mut seen: HashSet<&FieldName> = HashSet::new();
            let oversign: Vec<_> = selection
                .iter()
                .filter(|name| seen.insert(name))
                .cloned()
                .collect();

            selection.extend(oversign);
        }
        OversignedHeaders::Exhaustive => {
            let mut seen: HashSet<&FieldName> = HashSet::new();

            // first oversign all that have been signed already
            let mut to_oversign: Vec<_> = selection
                .iter()
                .filter(|name| seen.insert(name))
                .cloned()
                .collect();

            match signed_headers {
                s @ (SignedHeaders::Pick(names) | SignedHeaders::PickWithDefault(names)) => {
                    let mut tmp = if matches!(s, SignedHeaders::PickWithDefault(_)) {
                        default_signed_headers.iter().map(|n| n.as_ref()).collect()
                    } else {
                        vec![]
                    };
                    tmp.extend(names.iter().map(|n| n.as_ref()));

                    // then oversign all configured names
                    for n in &tmp {
                        if !seen.contains(n) {
                            to_oversign.push((*n).clone());
                        }
                    }

                    selection.extend(to_oversign);
                }
                SignedHeaders::All => {
                    // then oversign all that remain in the default set
                    for name in default_signed_headers.iter().map(|n| n.as_ref()) {
                        if !seen.contains(name) {
                            to_oversign.push((*name).clone());
                        }
                    }

                    selection.extend(to_oversign);
                }
            }
        }
    }

    selection
}

#[cfg(test)]
mod tests {
    use super::*;
    use viadkim::header::FieldBody;

    #[test]
    fn select_headers_pick_and_oversign_some() {
        let headers = make_header_fields(["from", "aa", "bb", "cc", "aa", "dd"]);

        let default = header_vec(["From", "To"]);
        let default_unsigned = vec![];
        let signed = SignedHeaders::PickWithDefault(header_vec(["Aa", "Bb", "Ee"]));
        let oversigned = OversignedHeaders::Pick(header_vec(["Bb", "From"]));

        let selection = select_headers(&headers, &signed, &oversigned, &default, &default_unsigned);

        assert!(selection
            .iter()
            .map(|n| n.as_ref())
            .eq(["aa", "bb", "aa", "from", "bb", "from"]));
    }

    #[test]
    fn select_headers_pick_and_oversign_all() {
        let headers = make_header_fields(["from", "aa", "bb", "cc", "aa", "dd"]);

        let default = header_vec(["From", "To"]);
        let default_unsigned = vec![];
        let signed = SignedHeaders::PickWithDefault(header_vec(["Aa", "Bb", "Ee"]));
        let oversigned = OversignedHeaders::Signed;

        let selection = select_headers(&headers, &signed, &oversigned, &default, &default_unsigned);

        assert!(selection
            .iter()
            .map(|n| n.as_ref())
            .eq(["aa", "bb", "aa", "from", "aa", "bb", "from"]));
    }

    #[test]
    fn select_headers_pick_and_oversign_exhaustive() {
        let headers = make_header_fields(["from", "aa", "bb", "cc", "aa", "dd"]);

        let default = header_vec(["From", "To"]);
        let default_unsigned = vec![];
        let signed = SignedHeaders::PickWithDefault(header_vec(["Aa", "Bb", "Ee"]));
        let oversigned = OversignedHeaders::Exhaustive;

        let selection = select_headers(&headers, &signed, &oversigned, &default, &default_unsigned);

        assert!(dbg!(&selection)
            .iter()
            .map(|n| n.as_ref())
            .eq(["aa", "bb", "aa", "from", "aa", "bb", "from", "To", "Ee"]));
    }

    #[test]
    fn select_headers_all_except_excluded() {
        let headers = make_header_fields(["from", "aa", "bb", "cc", "aa", "dd"]);

        let default = header_vec(["From", "To"]);
        let default_unsigned = header_vec(["cc", "dd"]);
        let signed = SignedHeaders::All;
        let oversigned = OversignedHeaders::Exhaustive;

        let selection = select_headers(&headers, &signed, &oversigned, &default, &default_unsigned);

        assert!(selection
            .iter()
            .map(|n| n.as_ref())
            .eq(["aa", "bb", "aa", "from", "aa", "bb", "from", "To"]));
    }

    fn make_header_fields(names: impl IntoIterator<Item = &'static str>) -> HeaderFields {
        let names: Vec<_> = names
            .into_iter()
            .map(|name| (FieldName::new(name).unwrap(), FieldBody::new(*b"").unwrap()))
            .collect();
        HeaderFields::new(names).unwrap()
    }

    fn header_vec(names: impl IntoIterator<Item = &'static str>) -> Vec<SignedFieldName> {
        names
            .into_iter()
            .map(|name| SignedFieldName::new(name).unwrap())
            .collect()
    }
}
