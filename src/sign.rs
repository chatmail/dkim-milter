use crate::{
    config::{
        model::{
            Expiration, OversignedHeaders, PartialSigningConfig, SignedFieldName, SignedHeaders,
            SigningConfig,
        },
        Config,
    },
    format::MailAddr,
    session::{DomainExpr, IdentityDomainExpr, LocalPartExpr, SenderMatch},
};
use indymilter::{ActionError, ContextActions, Status};
use log::{error, info};
use std::{collections::HashSet, error::Error, sync::Arc};
use viadkim::{
    crypto::SigningKey,
    header::{FieldName, HeaderFields},
    message_hash::BodyHasherStance,
    signature::{DomainName, Identity, Selector, SigningAlgorithm},
    signer::{self, BodyLength, HeaderSelection, SignRequest, SigningResult},
};

pub struct Signer {
    delegate: viadkim::Signer<Arc<SigningKey>>,
}

impl Signer {
    pub fn init(
        config: &Config,
        headers: HeaderFields,
        sender: &MailAddr,
        matches: Vec<SenderMatch>,
        connection_overrides: &PartialSigningConfig,
        recipient_overrides: &PartialSigningConfig,
    ) -> Result<Self, Box<dyn Error>> {
        assert!(!matches.is_empty());

        // step through matches and create SignRequest for each match

        // TODO limit number of matches processed - abort and warn if exceeded

        let mut requests = vec![];
        for match_ in matches {
            let (domain, identity) = get_identifiers(match_.domain, sender);
            let selector = match_.selector;
            let signing_key = match_.key;

            let final_overrides: PartialSigningConfig = match &match_.signing_config {
                Some(c) => {
                    // If there are per-sender/per-signature signing config
                    // overrides, combine them all together. The recipient
                    // overrides come last.
                    let x = connection_overrides.merged_with(c);
                    x.merged_with(recipient_overrides)
                }
                None => {
                    connection_overrides.merged_with(recipient_overrides)
                }
            };

            let signing_config = match config.signing_config.merged_with(&final_overrides) {
                Ok(config) => config,
                Err(e) => {
                    error!("failed to construct valid signing configuration, ignoring request: {e}");
                    continue;
                }
            };

            match make_sign_request(&signing_config, &headers, domain, identity, selector, signing_key) {
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

fn get_identifiers(domain: DomainExpr, sender: &MailAddr) -> (DomainName, Option<Identity>) {
    match domain {
        DomainExpr::Domain(domain) => (domain, None),
        DomainExpr::SenderDomain => (sender.domain.clone(), None),
        DomainExpr::Identity(identity) => {
            let local_part = identity.local_part.map(|lp| match lp {
                LocalPartExpr::LocalPart(lp) => lp,
                LocalPartExpr::SenderLocalPart => sender.local_part.clone(),
            });

            let (domain, identity_domain) = match identity.domain_part {
                IdentityDomainExpr::Domain(domain) => {
                    let domain2 = domain.clone();
                    (domain, domain2)
                }
                IdentityDomainExpr::SenderDomain => (sender.domain.clone(), sender.domain.clone()),
                IdentityDomainExpr::SplitDomain(subdomain, domain) => {
                    let d = format!("{}.{}", subdomain, domain);
                    let identity_domain = DomainName::new(d).unwrap();
                    (domain, identity_domain)
                }
            };

            let identity = Some(Identity {
                local_part: local_part.map(Into::into),
                domain: identity_domain,
            });

            (domain, identity)
        }
    }
}

fn make_sign_request(
    config: &SigningConfig,
    headers: &HeaderFields,
    domain: DomainName,
    identity: Option<Identity>,
    selector: Selector,
    signing_key: Arc<SigningKey>,
) -> Result<SignRequest<Arc<SigningKey>>, Box<dyn Error>> {
    let key_type = signing_key.key_type();

    let hash_algorithm = config.hash_algorithm;
    let alg = SigningAlgorithm::from_parts(key_type, hash_algorithm)
        .ok_or("invalid key type/hash algorithm pair")?;

    let mut request = SignRequest::new(domain, selector, alg, signing_key);

    request.identity = identity;

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
        OversignedHeaders::Extended => {
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
    fn select_headers_pick_and_oversign_extended() {
        let headers = make_header_fields(["from", "aa", "bb", "cc", "aa", "dd"]);

        let default = header_vec(["From", "To"]);
        let default_unsigned = vec![];
        let signed = SignedHeaders::PickWithDefault(header_vec(["Aa", "Bb", "Ee"]));
        let oversigned = OversignedHeaders::Extended;

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
        let oversigned = OversignedHeaders::Extended;

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
