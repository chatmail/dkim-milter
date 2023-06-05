use crate::{auth_results, config::RuntimeConfig, resolver::Resolver};
use indymilter::{ActionError, ContextActions, Status};
use log::info;
use std::{cmp, error::Error};
use viadkim::{
    header::HeaderFields,
    message_hash::BodyHasherStance,
    verifier::{self, VerificationResult, VerificationStatus, VerifierError},
};

pub struct Verifier {
    delegate: Option<viadkim::Verifier>,
}

impl Verifier {
    pub async fn init(runtime: &RuntimeConfig, headers: HeaderFields) -> Self {
        let fail_if_expired = runtime.config.fail_if_expired;

        let config = verifier::Config {
            fail_if_expired,
            ..Default::default()
        };

        let verifier = match &runtime.resolver {
            Resolver::Live(r) => viadkim::Verifier::process_header(r, &headers, &config).await,
            Resolver::Mock(r) => {
                viadkim::Verifier::process_header(r.as_ref(), &headers, &config).await
            }
        };

        Self { delegate: verifier }
    }

    pub fn process_body_chunk(&mut self, chunk: &[u8]) -> Result<Status, Box<dyn Error>> {
        let status = match &mut self.delegate {
            Some(verifier) => verifier.body_chunk(chunk),
            None => return Ok(Status::Skip),
        };

        Ok(if let BodyHasherStance::Done = status {
            Status::Skip
        } else {
            Status::Continue
        })
    }

    pub async fn finish(
        self,
        id: &str,
        authserv_id: &str,
        actions: &impl ContextActions,
    ) -> Result<Status, ActionError> {
        let sigs = if let Some(verifier) = self.delegate {
            verifier.finish()
        } else {
            vec![]
        };

        for sig in &sigs {
            // TODO

            let testing = "testing mode";

            let comment;
            let comment = match (auth_results::auth_results_reason_from_status(&sig.status), sig.testing) {
                (None, false) => "",
                (None, true) => {
                    comment = format!(" ({testing})");
                    &comment
                }
                (Some(reason), false) => {
                    comment = format!(" ({reason})");
                    &comment
                }
                (Some(reason), true) => {
                    comment = format!(" ({reason}; {testing})");
                    &comment
                }
            };

            info!(
                "{id}: verified signature from {}: {}{}",
                get_domain_from_verification_result(sig),
                sig.status.to_auth_results_kind(),
                comment
            );
        }

        let ar = auth_results::assemble_auth_results(authserv_id, sigs);

        actions
            .insert_header(0, "Authentication-Results", ar)
            .await?;

        Ok(Status::Continue)
    }
}

pub fn get_domain_from_verification_result(res: &VerificationResult) -> String {
    match &res.signature {
        Some(s) => s.domain.to_string(),
        None => {
            if let VerificationStatus::Failure(VerifierError::DkimSignatureHeaderFormat(e)) =
                &res.status
            {
                if let Some(d) = &e.domain {
                    return d.to_string();
                }
            }
            "unknown".to_string()
        }
    }
}

pub fn get_signature_prefix_from_verification_result(res: &VerificationResult) -> Option<String> {
    // TODO use minimal unique prefix instead of [..8]
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
