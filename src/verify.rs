use crate::{
    auth_results,
    config::{
        model::{RejectFailure, VerificationConfig},
        Config, SessionConfig,
    },
    format::EmailAddr,
    resolver::Resolver,
    session::FromAddrError,
};
use indymilter::{ContextActions, SetErrorReply, Status};
use log::{debug, info};
use std::{cmp, error::Error, net::IpAddr};
use viadkim::{
    header::HeaderFields,
    message_hash::BodyHasherStance,
    signature::DkimSignature,
    verifier::{self, VerificationError, VerificationResult, VerificationStatus},
};

pub struct Verifier {
    delegate: Option<viadkim::Verifier>,
    config: VerificationConfig,
}

impl Verifier {
    pub async fn init(
        session_config: &SessionConfig,
        headers: HeaderFields,
        ip: Option<IpAddr>,
        recipients: &[String],
    ) -> Self {
        let config = &session_config.config;

        let vconfig = assemble_verification_config(ip, recipients, config);

        let allow_expired = vconfig.allow_expired;
        let min_key_bits = vconfig.min_key_bits;
        let allow_sha1 = vconfig.allow_sha1;

        let config = verifier::Config {
            allow_expired,
            min_key_bits,
            allow_sha1,
            ..Default::default()
        };

        let verifier = match &session_config.resolver {
            Resolver::Live(r) => viadkim::Verifier::verify_header(r, &headers, &config).await,
            Resolver::Mock(r) => {
                viadkim::Verifier::verify_header(r.as_ref(), &headers, &config).await
            }
        };

        Self {
            delegate: verifier,
            config: vconfig,
        }
    }

    pub fn process_body_chunk(&mut self, chunk: &[u8]) -> Result<Status, Box<dyn Error>> {
        let status = match &mut self.delegate {
            Some(verifier) => verifier.process_body_chunk(chunk),
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
        config: &Config,
        authserv_id: &str,
        from_addresses: Option<&Result<Vec<EmailAddr>, FromAddrError>>,
        reply: &mut impl SetErrorReply,
        actions: &impl ContextActions,
    ) -> Result<Status, Box<dyn Error>> {
        let sigs = if let Some(verifier) = self.delegate {
            verifier.finish()
        } else {
            vec![]
        };

        #[derive(PartialEq)]
        enum SigStatus {
            Missing,  // no signature present
            Failing,  // no passing signature present
            Passing,  // a passing signature (not matching author domain) is present
            PassingFrom,  // a passing signature with author domain match is present
        }

        let mut sig_status = SigStatus::Missing;

        // log all sigs, and determine status for potential rejection

        for sig in &sigs {
            // first, update sig status
            let is_testing = sig.key_record.as_ref().map_or(false, |r| r.is_testing_mode());

            // DKIM key records in testing mode are treated as passing!

            match sig_status {
                SigStatus::Missing => {
                    // set status to Failing|Passing|PassingFrom as appropriate
                    if sig.status == VerificationStatus::Success || is_testing {
                        if is_author_matched_domain(sig.signature.as_ref(), from_addresses) {
                            sig_status = SigStatus::PassingFrom;
                        } else {
                            sig_status = SigStatus::Passing;
                        }
                    } else {
                        sig_status = SigStatus::Failing;
                    }
                }
                SigStatus::Failing => {
                    // check for Passing|PassingFrom and upgrade if appropriate
                    if sig.status == VerificationStatus::Success || is_testing {
                        if is_author_matched_domain(sig.signature.as_ref(), from_addresses) {
                            sig_status = SigStatus::PassingFrom;
                        } else {
                            sig_status = SigStatus::Passing;
                        }
                    }
                }
                SigStatus::Passing => {
                    // check for PassingFrom and upgrade if appropriate
                    if sig.status == VerificationStatus::Success || is_testing {
                        if is_author_matched_domain(sig.signature.as_ref(), from_addresses) {
                            sig_status = SigStatus::PassingFrom;
                        }
                    }
                }
                SigStatus::PassingFrom => {}  // no-op
            }

            // now log

            let testing = "test mode";

            let comment;
            let comment = match (
                auth_results::auth_results_reason_from_status(&sig.status),
                is_testing,
            ) {
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
                sig.status.to_dkim_auth_result(),
                comment
            );
        }

        // See RFC 7372, section 3.1 for these rejections.
        // We don't make distinction between passing and acceptable signatures,
        // so use these status codes slightly differently.

        let rejects = &self.config.reject_failures.0;

        if rejects.contains(&RejectFailure::Missing) && sig_status == SigStatus::Missing {
            if config.dry_run {
                debug!("{id}: rejected message missing signature [dry run, not done]");
                return Ok(Status::Accept);
            } else {
                debug!("{id}: rejected message missing signature");
                reply.set_error_reply("550", Some("5.7.20"), ["No DKIM signature found"])?;
                return Ok(Status::Reject);
            }
        }

        if rejects.contains(&RejectFailure::Failing) && sig_status == SigStatus::Failing {
            if config.dry_run {
                debug!("{id}: rejected message without acceptable signature [dry run, not done]");
                return Ok(Status::Accept);
            } else {
                debug!("{id}: rejected message without acceptable signature");
                reply.set_error_reply("550", Some("5.7.21"), ["No acceptable DKIM signature found"])?;
                return Ok(Status::Reject);
            }
        }

        if rejects.contains(&RejectFailure::AuthorMismatch) && sig_status == SigStatus::Passing {
            if config.dry_run {
                debug!("{id}: rejected message without acceptable author-matched signature [dry run, not done]");
                return Ok(Status::Accept);
            } else {
                debug!("{id}: rejected message without acceptable author-matched signature");
                reply.set_error_reply("550", Some("5.7.22"), ["No valid author-matched DKIM signature found"])?;
                return Ok(Status::Reject);
            }
        }

        let ar = auth_results::assemble_auth_results(authserv_id, sigs);

        if config.dry_run {
            debug!("{id}: adding Authentication-Results header [dry run, not done]");
        } else {
            debug!("{id}: adding Authentication-Results header");
            actions
                .insert_header(0, "Authentication-Results", ar)
                .await?;
        }

        Ok(Status::Continue)
    }
}

fn assemble_verification_config(
    ip: Option<IpAddr>,
    recipients: &[String],
    config: &Config,
) -> VerificationConfig {
    // TODO avoid all the cloning

    let mut base_config = &config.verification_config;

    let merged_config;
    if let Some(ip) = ip {
        if let Some(connection_overrides) = &config.connection_overrides {
            for entry in connection_overrides {
                if entry.net.contains(&ip) {
                    merged_config = base_config.combine_with(&entry.config.verification_config);
                    base_config = &merged_config;
                    break;
                }
            }
        }
    }

    // TODO duplicated
    let merged_config2;
    'outer: for recipient in recipients {
        if let Some(recipient_overrides) = &config.recipient_overrides {
            for overrides in &recipient_overrides.entries {
                if overrides.expr.is_match(recipient) {
                    merged_config2 = base_config.combine_with(&overrides.config.verification_config);
                    base_config = &merged_config2;
                    break 'outer;
                }
            }
        }
    }

    base_config.clone()
}

pub fn get_domain_from_verification_result(res: &VerificationResult) -> String {
    match &res.signature {
        Some(s) => s.domain.to_string(),
        None => {
            if let VerificationStatus::Failure(VerificationError::DkimSignatureFormat(e)) =
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
            let s = viadkim::encode_base64(&sig.signature_data);
            let s = &s[..(cmp::min(8, s.len()))];
            Some(s.into())
        }
        None => {
            if let VerificationStatus::Failure(VerificationError::DkimSignatureFormat(e)) =
                &res.status
            {
                if let Some(s) = &e.signature_data {
                    let s = &s[..(cmp::min(8, s.len()))];
                    return Some(s.into());
                }
            }
            None
        }
    }
}

fn is_author_matched_domain(
    sig: Option<&DkimSignature>,
    from_addresses: Option<&Result<Vec<EmailAddr>, FromAddrError>>,
) -> bool {
    let domain = match sig {
        Some(sig) => &sig.domain,
        None => return false,
    };

    let from_addresses = match from_addresses {
        Some(Ok(addrs)) => addrs,
        _ => return false,
    };

    for addr in from_addresses {
        if addr.domain.eq_or_subdomain_of(domain) {
            return true;
        }
    }

    false
}
