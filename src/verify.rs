// DKIM Milter – milter for DKIM signing and verification
// Copyright © 2022–2024 David Bürgin <dbuergin@gluet.ch>
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
        model::{
            PartialVerificationConfig, RejectFailure, SignedFieldNameWithQualifier,
            VerificationConfig,
        },
        Config, SessionConfig,
    },
    format::MailAddr,
    resolver::Resolver,
    util::BoxError,
};
use indymilter::{ContextActions, SetErrorReply, Status};
use log::{debug, info};
use viadkim::{
    header::{FieldName, HeaderFields},
    message_hash::BodyHasherStance,
    record::{DkimKeyRecord, SelectorFlag},
    signature::DkimSignature,
    verifier::{self, VerificationError, VerificationResult, VerificationStatus},
};

pub struct Verifier {
    delegate: Option<viadkim::Verifier>,
    config: VerificationConfig,
    from_addresses: Vec<MailAddr>,
}

impl Verifier {
    pub async fn init(
        session_config: &SessionConfig,
        headers: HeaderFields,
        from_addresses: Vec<MailAddr>,
        connection_overrides: &PartialVerificationConfig,
        recipient_overrides: &PartialVerificationConfig,
    ) -> Self {
        let config = &session_config.config;

        let lookup_timeout = config.lookup_timeout;

        let c = connection_overrides.merged_with(recipient_overrides);
        let vconfig = config.verification_config.merged_with(&c);

        let allow_expired = vconfig.allow_expired;
        let allow_sha1 = vconfig.allow_sha1;
        let allow_timestamp_in_future = vconfig.allow_timestamp_in_future;
        let forbid_unsigned_content = vconfig.forbid_unsigned_content;
        let max_signatures = vconfig.max_signatures_to_verify;
        let min_key_bits = vconfig.min_rsa_key_bits;
        let time_tolerance = vconfig.time_tolerance;
        let (headers_required_in_signature, headers_forbidden_to_be_unsigned) =
            make_signed_headers_specs(&vconfig.required_signed_headers);

        let config = verifier::Config {
            allow_expired,
            allow_sha1,
            allow_timestamp_in_future,
            forbid_unsigned_content,
            headers_forbidden_to_be_unsigned,
            headers_required_in_signature,
            lookup_timeout,
            max_signatures,
            min_key_bits,
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
            from_addresses,
        }
    }

    pub fn process_body_chunk(&mut self, chunk: &[u8]) -> Status {
        let status = match &mut self.delegate {
            Some(verifier) => verifier.process_body_chunk(chunk),
            None => return Status::Skip,
        };

        if let BodyHasherStance::Done = status {
            Status::Skip
        } else {
            Status::Continue
        }
    }

    pub async fn finish(
        self,
        id: &str,
        config: &Config,
        authserv_id: &str,
        reply: &mut impl SetErrorReply,
        actions: &impl ContextActions,
    ) -> Result<Status, BoxError> {
        let sigs = if let Some(verifier) = self.delegate {
            verifier.finish()
        } else {
            vec![]
        };

        let rejects = &self.config.reject_failures.0;

        let exact = rejects.contains(&RejectFailure::AuthorMismatchStrict);
        let mut astatus = AggregateStatus::NoSignature;

        // For all signatures, determine status for potential rejection and log
        // verification result.
        for sig in &sigs {
            update_aggregate_status(&mut astatus, sig, &self.from_addresses, exact);

            let is_testing = matches!(&sig.key_record, Some(r) if r.is_testing());
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
                "{id}: {}: {}{}",
                get_domain_from_verification_result(sig),
                sig.status.to_dkim_result(),
                comment
            );
        }

        // See RFC 7372, section 3.1 for these rejections.
        // We don’t make the distinction between passing and acceptable
        // signatures, so use these status codes slightly differently.

        if rejects.contains(&RejectFailure::Missing) && astatus == AggregateStatus::NoSignature {
            if config.dry_run {
                debug!("{id}: rejected message without signature [dry run, not done]");
                return Ok(Status::Continue);
            } else {
                debug!("{id}: rejected message without signature");
                reply.set_error_reply("550", Some("5.7.20"), ["No DKIM signature found"])?;
                return Ok(Status::Reject);
            }
        }

        if rejects.contains(&RejectFailure::NoPass) && astatus == AggregateStatus::AllFailing {
            if config.dry_run {
                debug!("{id}: rejected message without acceptable signature [dry run, not done]");
                return Ok(Status::Continue);
            } else {
                debug!("{id}: rejected message without acceptable signature");
                reply.set_error_reply("550", Some("5.7.21"), ["No acceptable DKIM signature found"])?;
                return Ok(Status::Reject);
            }
        }

        if (rejects.contains(&RejectFailure::AuthorMismatch)
            || rejects.contains(&RejectFailure::AuthorMismatchStrict))
            && astatus == AggregateStatus::Passing
        {
            if config.dry_run {
                debug!("{id}: rejected message without acceptable author-matched signature [dry run, not done]");
                return Ok(Status::Continue);
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

fn make_signed_headers_specs(
    names: &[SignedFieldNameWithQualifier],
) -> (Vec<FieldName>, Vec<FieldName>) {
    let mut headers_required_in_signature = vec![];
    let mut headers_forbidden_to_be_unsigned = vec![];

    for name in names {
        match name {
            SignedFieldNameWithQualifier::Bare(name) => {
                headers_required_in_signature.push(name.as_ref().clone());
            }
            SignedFieldNameWithQualifier::Plus(name) => {
                headers_required_in_signature.push(name.as_ref().clone());
                headers_forbidden_to_be_unsigned.push(name.as_ref().clone());
            }
            SignedFieldNameWithQualifier::Asterisk(name) => {
                headers_forbidden_to_be_unsigned.push(name.as_ref().clone());
            }
        }
    }

    (headers_required_in_signature, headers_forbidden_to_be_unsigned)
}

/// Verification status of the aggregate of signatures.
#[derive(PartialEq)]
enum AggregateStatus {
    /// Starting state: no signature present.
    NoSignature,
    /// No passing signature present.
    AllFailing,
    /// A passing signature not matching the author domain is present.
    Passing,
    /// A passing signature with author domain match is present.
    PassingFrom,
}

/// Advances the ‘aggregate status’ state according to the incoming verification
/// result status.
fn update_aggregate_status(
    current_status: &mut AggregateStatus,
    res: &VerificationResult,
    from_addrs: &[MailAddr],
    exact: bool,
) {
    let signature = res.signature.as_ref();
    let record = res.key_record.as_deref();

    // DKIM public key records in testing mode are treated as passing.
    let passing =
        res.status == VerificationStatus::Success || matches!(record, Some(r) if r.is_testing());

    match current_status {
        AggregateStatus::NoSignature => {
            // When no signature has yet been seen, progress to state
            // AllFailing|Passing|PassingFrom as appropriate.
            if passing {
                if has_author_match(signature, record, from_addrs, exact) {
                    *current_status = AggregateStatus::PassingFrom;
                } else {
                    *current_status = AggregateStatus::Passing;
                }
            } else {
                *current_status = AggregateStatus::AllFailing;
            }
        }
        AggregateStatus::AllFailing => {
            // When only failing signatures have been seen, progress to state
            // Passing|PassingFrom as appropriate.
            if passing {
                if has_author_match(signature, record, from_addrs, exact) {
                    *current_status = AggregateStatus::PassingFrom;
                } else {
                    *current_status = AggregateStatus::Passing;
                }
            }
        }
        AggregateStatus::Passing => {
            // When only a passing signature with non-author domain has been
            // seen, progress to state PassingFrom if possible.
            if passing && has_author_match(signature, record, from_addrs, exact) {
                *current_status = AggregateStatus::PassingFrom;
            }
        }
        AggregateStatus::PassingFrom => {}
    }
}

fn get_domain_from_verification_result(res: &VerificationResult) -> String {
    match &res.signature {
        Some(s) => s.domain.to_string(),
        None => {
            if let VerificationStatus::Failure(VerificationError::DkimSignatureFormat(e)) =
                &res.status
            {
                // Consider sanitising an odd-shaped domain here.
                if let Some(d) = &e.domain_str {
                    return d.as_ref().into();
                }
            }
            "unknown".into()
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
        if let Some(s) = &e.signature_data_str {
            return sanitize_b_tag_value(s).or_else(|| Some(s.as_ref().into()));
        }
    }

    None
}

// If the b tag string content consists of what looks like (perhaps only
// incomplete) Base64, then strip whitespace as would usually happen.
fn sanitize_b_tag_value(s: &str) -> Option<String> {
    fn is_wsp(c: char) -> bool {
        c == '\t' || c == ' '
    }
    fn is_in_base64_alphabet(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')
    }

    let mut result = String::new();

    for (i, mut part) in s.split("\r\n").enumerate() {
        if i > 0 {
            part = part.strip_prefix(is_wsp)?;
        }
        for c in part.chars() {
            if is_in_base64_alphabet(c) {
                result.push(c);
            } else if !is_wsp(c) {
                return None;
            }
        }
    }

    Some(result)
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
        let this_str = match this_str {
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
        'others:
        for (other_index, other_str) in sigs {
            if other_index == this_index {
                continue;
            }

            let other_str = match other_str {
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

// What is an ‘author-matched signature’ (RFC 7372) or an ‘Author Domain
// Signature’ (RFC 6541 [ATPS])? It’s not well defined really, but see also
// remarks in RFC 6376, sections 3.10f. and 8.14. We take it to mean a signature
// with signing domain matching (subdomain or exact domain, see below) the
// message author’s (From) domain.
fn has_author_match(
    sig: Option<&DkimSignature>,
    record: Option<&DkimKeyRecord>,
    from_addrs: &[MailAddr],
    exact: bool,
) -> bool {
    let domain = match sig {
        Some(sig) => &sig.domain,
        None => return false,
    };

    let mut ascii_domain = None;

    for addr in from_addrs {
        if addr.domain.eq_or_subdomain_of(domain) {
            // We have at least an author subdomain match. But do we need an
            // exact domain match? If the record has `t=s` then yes.
            if exact || matches!(record, Some(r) if r.flags.contains(&SelectorFlag::NoSubdomains)) {
                let adomain = ascii_domain.get_or_insert_with(|| domain.to_ascii());
                if addr.domain.to_ascii() == *adomain {
                    return true;
                }
            } else {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_b_tag_value_ok() {
        assert_eq!(
            sanitize_b_tag_value("Ab9\r\n 2/q").as_deref(),
            Some("Ab92/q")
        );
        assert_eq!(sanitize_b_tag_value("invalid\r\n _#!"), None);
    }

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

        assert_eq!(
            result,
            [
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
            ]
        );
    }
}
