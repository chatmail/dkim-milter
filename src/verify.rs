use crate::{
    auth_results,
    config::{
        model::{PartialVerificationConfig, RejectFailure, VerificationConfig},
        Config, SessionConfig,
    },
    format::MailAddr,
    resolver::Resolver,
    session::SenderAddrError,
};
use indymilter::{ContextActions, SetErrorReply, Status};
use log::{debug, info};
use std::error::Error;
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
        connection_overrides: &PartialVerificationConfig,
        recipient_overrides: &PartialVerificationConfig,
    ) -> Self {
        let config = &session_config.config;

        let x = connection_overrides.merged_with(recipient_overrides);
        let vconfig = config.verification_config.merged_with(&x);

        let allow_expired = vconfig.allow_expired;
        let allow_sha1 = vconfig.allow_sha1;
        let allow_timestamp_in_future = vconfig.allow_timestamp_in_future;
        let forbid_unsigned_content = vconfig.forbid_unsigned_content;
        let lookup_timeout = vconfig.lookup_timeout;
        let max_signatures = vconfig.max_signatures;
        let min_key_bits = vconfig.min_rsa_key_bits;
        let time_tolerance = vconfig.time_tolerance;
        let required_signed_headers = vconfig.required_signed_headers.iter()
            .map(|h| h.as_ref().clone())
            .collect();

        let config = verifier::Config {
            allow_expired,
            allow_sha1,
            allow_timestamp_in_future,
            forbid_unsigned_content,
            lookup_timeout,
            max_signatures,
            min_key_bits,
            required_signed_headers,
            time_tolerance,
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
        from_addresses: Option<&Result<Vec<MailAddr>, SenderAddrError>>,
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
            let is_testing = matches!(&sig.key_record, Some(r) if r.is_testing_mode());

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

pub fn get_domain_from_verification_result(res: &VerificationResult) -> String {
    // TODO convert to U-form
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

// Signature prefixes recorded in header.b are specified in RFC 6008. The RFC
// does not say much about edge cases. The returned signature prefixes may not
// be unique. For example, if two b= tags have identical values (this happens in
// practice due to clueless administrators) there is no unique prefix, they will
// remain identical.
pub fn compute_signature_prefixes(sigs: &[VerificationResult]) -> Vec<Option<String>> {
    let sigs: Vec<_> = sigs
        .iter()
        .map(|sig| (sig.index, make_b_string(sig)))
        .collect();

    compute_signature_prefixes_internal(&sigs, 8)
}

fn make_b_string(r: &VerificationResult) -> Option<String> {
    // If proper DKIM signature data is available, re-encode the signature bytes
    // to the original Base64 string.
    if let Some(sig) = &r.signature {
        return Some(viadkim::encode_base64(&sig.signature_data));
    }

    // Else try to use whatever was salvaged as a string from the b= tag.
    // Careful, this could be any (malicious) thing.
    if let VerificationStatus::Failure(VerificationError::DkimSignatureFormat(e)) = &r.status {
        // TODO may need to strip whitespace if impl in viadkim changes
        if let Some(s) = &e.signature_data {
            return Some(s.as_ref().into());
        }
    }

    None
}

// Design note: The purpose of the header.b prefix is identifying a signature
// unambiguously. However, some values cannot be disambiguated clearly. For
// example, when value "abcdefgh" is a prefix of value "abcdefghijk", then the
// first value by itself is ambiguous. In such cases we have decided to make the
// longer value one character longer, "abcdefghi". Consumers of the prefixes
// could then select unambiguously by picking the longer prefixes first.

fn compute_signature_prefixes_internal(
    sigs: &[(usize, Option<String>)],
    min_len: usize,
) -> Vec<Option<String>> {
    assert!(min_len > 0);

    let mut result = Vec::with_capacity(sigs.len());

    // This is surprisingly complicated. This algorithm is quadratic, for now
    // this is acceptable because there is only a limited number of results and
    // no expensive computation happening.

    for (this_index, this_str) in sigs {
        let this_str = match this_str.as_deref() {
            Some(s) => s,
            None => {
                // This verification result does not have a b= string.
                result.push(None);
                continue;
            }
        };

        let mut this_indices = this_str.char_indices();

        // `i` is the byte offset of the char *after* min_len chars.
        let (i, mut this_c) = match this_indices.nth(min_len) {
            Some(x) => x,
            None => {
                // If the b= string is only of minimum size, use it entirely.
                result.push(Some(this_str.into()));
                continue;
            }
        };

        // This is the initial minimum prefix if the b= string has > min_len
        // chars. It is min_len (8) chars long.
        let mut this_prefix = &this_str[..i];

        // Step through all *other* signatures and use them to determine final
        // header.b value of this signature.
        'others: for (other_index, other_str) in sigs {
            if other_index == this_index {
                continue;
            }

            let other_str = match other_str.as_deref() {
                Some(s) => s,
                None => continue,
            };

            let other_rest = match other_str.strip_prefix(this_prefix) {
                Some(s) => s,
                None => {
                    // The other b= string does not impact prefix computation.
                    continue;
                }
            };

            // The other b= string has the same prefix as this b= string.
            // Complication! Computation!

            let mut other_rest_indices = other_rest.char_indices();

            let (_, mut other_c) = match other_rest_indices.next() {
                Some(x) => x,
                None => {
                    // The other b= string is equal to the prefix. Disambiguate
                    // by making the prefix one char longer.
                    let x = this_indices.next().map_or(this_str.len(), |(n, _)| n);
                    this_prefix = &this_str[..x];
                    continue;
                }
            };

            // Finally, we can now compare the remainder of the b= strings until
            // we find a discrepancy.

            while this_c == other_c {
                match (this_indices.next(), other_rest_indices.next()) {
                    (None, _) => {
                        // This b= string is identical to or a prefix of the
                        // other b= string, disambiguation is not possible. This
                        // follows OpenDKIM, where the identical strings
                        // condition was added in a bug fix release with
                        // comment: ‘In the weird case of duplicate signatures,
                        // constrain the size of the resulting "header.b"
                        // value.’
                        continue 'others;
                    }
                    (Some(_), None) => {
                        // The other b= string was a prefix of our string. Break
                        // to make this prefix one char longer.
                        break;
                    }
                    (Some((_, this_c_next)), Some((_, other_c_next))) => {
                        this_c = this_c_next;
                        other_c = other_c_next;
                    }
                }
            }

            // The b= strings diverged. Make this_prefix one char longer.
            let x = this_indices.next().map_or(this_str.len(), |(n, _)| n);
            this_prefix = &this_str[..x];
        }

        result.push(Some(this_prefix.into()));
    }

    assert_eq!(result.len(), sigs.len());

    result
}

fn is_author_matched_domain(
    sig: Option<&DkimSignature>,
    from_addresses: Option<&Result<Vec<MailAddr>, SenderAddrError>>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_signature_prefixes_mixed() {
        let sigs = [
            Some("𝔞b𝔠".into()),
            None,
            Some("𝔞b𝔠d𝔢".into()),
            Some("p𝔮r𝔰t𝔲".into()),
            Some("p𝔮r𝔰T𝔲".into()),
            Some("p𝔮r𝔰t𝔵y".into()),
            Some("p𝔮r𝔰t𝔲v𝔴".into()),
            Some("p𝔮r𝔰".into()),
            Some("9876543".into()),
            Some("9876543".into()),
            Some("123456".into()),
            Some("12345".into()),
        ];
        let sigs: Vec<_> = (0..).zip(sigs).collect();

        let result = compute_signature_prefixes_internal(&sigs, 4);

        assert_eq!(result, [
            Some("𝔞b𝔠".into()),
            None,
            Some("𝔞b𝔠d".into()),
            Some("p𝔮r𝔰t𝔲".into()),
            Some("p𝔮r𝔰T".into()),
            Some("p𝔮r𝔰t𝔵".into()),
            Some("p𝔮r𝔰t𝔲v".into()),
            Some("p𝔮r𝔰".into()),
            Some("9876".into()),
            Some("9876".into()),
            Some("123456".into()),
            Some("1234".into()),
        ]);
    }
}
