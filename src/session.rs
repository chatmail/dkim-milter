use crate::{auth_results, config::Config, format, resolver::Resolver};
use bstr::ByteSlice;
use bytes::Bytes;
use indymilter::{ContextActions, Status};
use std::{borrow::Cow, mem, net::IpAddr, cmp, sync::Arc};
use tracing::{debug, error, info};
use viadkim::{
    canon::BodyCanonStatus,
    crypto::KeyType,
    header::{FieldBody, FieldName, HeaderFields},
    signature::DomainName,
    verifier::{VerificationResult, VerifierError, VerificationStatus},
    signer::{SigningStatus},
    Signer, SigningRequest, Verifier,
};

#[derive(Clone, Copy)]
pub enum Mode {
    Signing,
    Verifying,
}

// TODO
pub struct Session {
    config: Arc<Config>,

    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub auth: bool,
    pub queue_id: String,
    from_domain: Option<DomainName>,

    mode: Mode,

    verifier: Option<Verifier>,
    signer: Option<Signer>,

    headers: Vec<(FieldName, FieldBody)>,
}

impl Session {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,

            ip: None,
            hostname: None,
            auth: false,
            queue_id: "NONE".into(),
            from_domain: None,

            mode: Mode::Verifying,

            verifier: None,
            signer: None,

            headers: vec![],
        }
    }

    pub fn handle_header(
        &mut self,
        id: &str,
        name: Cow<'_, str>,
        value: Vec<u8>,
    ) -> Result<Status, ()> {
        // convert milter newlines to SMTP CRLF
        let value = value.replace("\n", "\r\n");

        // extract From header
        if name.eq_ignore_ascii_case("From") {
            if self.from_domain.is_some() {
                debug!("{id}: multiple From header fields");
                return Ok(Status::Accept);
            }
            match format::parse_header_from_domain(&value) {
                Ok(domain) => {
                    self.from_domain = Some(domain);
                }
                Err(e) => {
                    debug!("{id}: unusable From header field: {e:?}");
                    return Ok(Status::Accept);
                }
            }
        }

        // update header fields, ignore unusable inputs
        if let (Ok(name), Ok(value)) = (FieldName::new(name), FieldBody::new(value)) {
            self.headers.push((name, value));
        }

        Ok(Status::Continue)
    }

    pub async fn prepare_processing(&mut self, id: &str) -> Result<Status, ()> {
        let domain_to_sign = &self.config.domain_to_sign;

        // local and authenticated senders are authorised
        let authzd = self.ip.filter(|i| i.is_loopback()).is_some() || self.auth;

        let from_domain = match self.from_domain.as_ref() {
            Some(from_domain) => from_domain,
            None => {
                debug!("{id}: no From header field in message");
                return Ok(Status::Accept);
            }
        };

        debug!("{id}: From domain is: <{}>", from_domain);

        // signing mode if authorised and right domain to sign in From
        self.mode = if authzd && from_domain.as_ref().eq_ignore_ascii_case(domain_to_sign) {
            debug!("{id}: signing mode");
            Mode::Signing
        } else {
            debug!("{id}: verifying mode");
            Mode::Verifying
        };

        let headers = mem::take(&mut self.headers);
        let headers = match HeaderFields::new(headers) {
            Ok(h) => h,
            Err(e) => {
                debug!("{id}: unusable header fields: {e:?}");
                return Ok(Status::Accept);
            }
        };

        match self.mode {
            Mode::Signing => {
                let signer = self.prepare_signer(headers)?;

                self.signer = Some(signer);
            }
            Mode::Verifying => {
                let verifier = self.prepare_verifier(headers).await?;

                self.verifier = Some(verifier);
            }
        }

        Ok(Status::Continue)
    }

    fn prepare_signer(&mut self, headers: HeaderFields) -> Result<Signer, ()> {
        let domain = DomainName::new(&self.config.domain_to_sign).unwrap();

        let key_id_rsa = self
            .config
            .keys_path_to_id
            .get(&self.config.rsa_key_path)
            .ok_or(())?;
        let request_rsa =
            SigningRequest::new(domain.clone(), "rsa.2022".into(), KeyType::Rsa, *key_id_rsa);

        let key_id_ed25519 = self
            .config
            .keys_path_to_id
            .get(&self.config.ed25519_key_path)
            .ok_or(())?;
        let request_ed25519 = SigningRequest::new(
            domain.clone(),
            "ed25519.2022".into(),
            KeyType::Ed25519,
            *key_id_ed25519,
        );

        let signer =
            Signer::prepare_signing(vec![request_rsa, request_ed25519], headers).map_err(|_| ())?;

        Ok(signer)
    }

    async fn prepare_verifier(&mut self, headers: HeaderFields) -> Result<Verifier, ()> {
        let resolver = Resolver::new();
        let config = Default::default();

        let verifier = Verifier::process_headers(&resolver, &headers, &config).await;

        Ok(verifier)
    }

    pub fn process_body_chunk(&mut self, chunk: Bytes) -> Result<Status, ()> {
        // Feed body chunks into processor
        // When l= limit is reached return Skip

        let status = match self.mode {
            Mode::Signing => {
                let signer = self.signer.as_mut().unwrap();
                signer.body_chunk(chunk.as_ref())
            }
            Mode::Verifying => {
                let verifier = self.verifier.as_mut().unwrap();
                verifier.body_chunk(chunk.as_ref())
            }
        };

        Ok(if let BodyCanonStatus::Done = status {
            Status::Skip
        } else {
            Status::Continue
        })
    }

    pub async fn finish_message(
        mut self,
        id: &str,
        actions: &impl ContextActions,
    ) -> Result<Status, ()> {
        match self.mode {
            Mode::Signing => {
                let signer = self.signer.take().unwrap();
                let key_store = &self.config.keys_id_to_key;
                let sigs = signer.finish(key_store).await;

                // insert headers in reverse:
                for res in sigs.into_iter().rev() {
                    let sstatus = res.status;
                    match sstatus {
                        SigningStatus::Error { error } => {
                            let _e = error;
                            error!("{id}: failed to sign message for {}", "TODO-DOMAIN");
                        }
                        SigningStatus::Success { signature, header_name, header_value } => {
                            info!("{id}: signed message for {}", signature.domain);

                            let hdr_name = header_name;
                            let hdr = header_value;

                            // convert SMTP CRLF to milter line endings
                            let hdr = hdr.replace("\r\n", "\n");

                            actions
                                .insert_header(0, hdr_name, hdr)
                                .await
                                .map_err(|_| ())?;
                        }
                    }
                }
            }
            Mode::Verifying => {
                let verifier = self.verifier.take().unwrap();
                let sigs: Vec<VerificationResult> = verifier.finish();

                for sig in &sigs {
                    // TODO
                    let result = auth_results::auth_results_kind_from_status(&sig.status).as_str();

                    info!(
                        "{id}: verified signature from {}: {}",
                        get_domain_from_verification_result(sig),
                        result
                    );
                }

                if !sigs.is_empty() {
                    let ar = auth_results::assemble_auth_results(&self.config.authserv_id, sigs);

                    actions
                        .insert_header(0, "Authentication-Results", ar)
                        .await
                        .map_err(|_| ())?;
                }
            }
        }

        Ok(Status::Continue)
    }
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
    // TODO do not use base64 crate, provide this in viadkim
    match &res.signature {
        Some(sig) => {
            let s = base64::encode(&sig.signature_data);
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
