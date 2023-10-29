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

use crate::{format, verify};
use std::{
    borrow::Cow,
    error::Error,
    fmt::Write,
    str::{self, FromStr},
};
use viadkim::{
    record::DkimKeyRecordError,
    signature::{DkimSignature, DkimSignatureError, DomainName, Identity},
    verifier::{DkimResult, VerificationError, VerificationResult, VerificationStatus},
};

// Note: Some things initially copied from SPF Milter, may consolidate later.

pub fn extract_authserv_id(value: &[u8]) -> Option<Cow<'_, str>> {
    // *authserv-id* is a lexical token of kind `value` as defined in RFC 2045,
    // section 5.1, that is, either a `token` or a quoted string. Immediately
    // before the *authserv-id* there may be a CFWS.
    let value = format::strip_cfws_loose(value).unwrap_or(value);

    if let Some(rest) = format::strip_mime_value(value) {
        // Directly after the *authserv-id* may come either a semicolon or
        // another CFWS. Validation proceeds no further than this.
        if rest.starts_with(b";") || format::strip_cfws_loose(rest).is_some() {
            // We have a match. If it is a quoted string, now it needs to be
            // decoded to be in a form comparable with another *authserv-id*.
            let authserv_id = &value[..(value.len() - rest.len())];
            let authserv_id = str::from_utf8(authserv_id).ok()?;
            return Some(if authserv_id.starts_with('"') {
                format::decode_quoted_string(authserv_id).into()
            } else {
                authserv_id.into()
            });
        }
    }

    None
}

pub fn assemble_auth_results(authserv_id: &str, sigs: Vec<VerificationResult>) -> String {
    let mut result = String::new();

    write!(result, " {}", format::encode_mime_value(authserv_id)).unwrap();

    if sigs.is_empty() {
        let ar = DkimResult::None;
        write!(result, "; dkim={ar}").unwrap();
    } else {
        let signature_prefixes = verify::compute_signature_prefixes(&sigs);

        for (sig, prefix) in sigs.into_iter().zip(signature_prefixes) {
            format_resinfo_into_string(&mut result, sig, prefix);
        }
    }

    result
}

fn format_resinfo_into_string(
    result: &mut String,
    sig: VerificationResult,
    prefix: Option<String>,
) {
    let ar = sig.status.to_dkim_result();

    write!(result, ";\n\tdkim={ar}").unwrap();

    if matches!(&sig.key_record, Some(r) if r.is_testing()) {
        write!(result, " (test mode)").unwrap();
    }

    if let Some(reason) = auth_results_reason_from_status(&sig.status) {
        write!(result, " reason={}", format::encode_mime_value(&reason)).unwrap();
    }

    let (signature, error) = get_signature_or_error_data(&sig);

    format_identities_into_string(result, signature, error);

    // Is there more data to display on an additional line?
    if signature.is_some()
        || matches!(error, Some(e) if e.algorithm_str.is_some() || e.selector_str.is_some())
        || prefix.is_some()
    {
        result.push_str("\n\t");

        format_algorithm_into_string(result, signature, error);

        format_selector_into_string(result, signature, error);

        if let Some(s) = prefix {
            write!(result, " header.b={}", format::encode_mime_value(&s)).unwrap();
        }
    }
}

pub fn auth_results_reason_from_status(status: &VerificationStatus) -> Option<String> {
    match status {
        VerificationStatus::Success => None,
        VerificationStatus::Failure(error) => {
            // For now display only the source error, this works well with the
            // current Display strings.
            match error {
                VerificationError::KeyRecordFormat(error) => {
                    // For errors due to key record format append ‘… in key
                    // record’ – however, this might ‘break’ if message changes!
                    Some(match error {
                        DkimKeyRecordError::TagListFormat
                        | DkimKeyRecordError::MisplacedVersionTag
                        | DkimKeyRecordError::IncompatibleVersion
                        | DkimKeyRecordError::InvalidHashAlgorithm
                        | DkimKeyRecordError::NoSupportedHashAlgorithms
                        | DkimKeyRecordError::UnsupportedKeyType
                        | DkimKeyRecordError::InvalidQuotedPrintable
                        | DkimKeyRecordError::InvalidBase64
                        | DkimKeyRecordError::InvalidServiceType
                        | DkimKeyRecordError::NoSupportedServiceTypes
                        | DkimKeyRecordError::InvalidFlag
                        | DkimKeyRecordError::MissingKeyTag => format!("{error} in key record"),
                        _ => error.to_string(),
                    })
                }
                error => Some(match error.source() {
                    Some(e) => e.to_string(),
                    None => error.to_string(),
                }),
            }
        }
    }
}

fn get_signature_or_error_data(
    sig: &VerificationResult,
) -> (Option<&DkimSignature>, Option<&DkimSignatureError>) {
    if let Some(signature) = &sig.signature {
        (Some(signature), None)
    } else if let VerificationStatus::Failure(VerificationError::DkimSignatureFormat(error)) =
        &sig.status
    {
        (None, Some(error))
    } else {
        (None, None)
    }
}

fn format_identities_into_string(
    result: &mut String,
    signature: Option<&DkimSignature>,
    error: Option<&DkimSignatureError>,
) {
    // header.d is *always* included, being the main payload of a DKIM
    // signature. If it is not known, "unknown" is substituted.

    // header.i is synthesised if possible, because of RFC 6376, section 6.1.1:
    // ‘If the DKIM-Signature header field does not contain the "i=" tag, the
    // Verifier MUST behave as though the value of that tag were "@d", where "d"
    // is the value from the "d=" tag.’

    if let Some(signature) = signature {
        let domain = &signature.domain;

        format_domain_into_string(result, domain);

        if let Some(identity) = &signature.identity {
            format_identity_into_string(result, identity);
        } else {
            let id = Identity::from_domain(domain.clone());
            format_identity_into_string(result, &id);
        }
    } else if let Some(error) = error {
        let mut valid_domain = None;

        if let Some(domain_str) = &error.domain_str {
            if let Ok(domain) = DomainName::from_str(domain_str) {
                let d = valid_domain.insert(domain);
                format_domain_into_string(result, d);
            } else {
                write!(result, " header.d={}", format::encode_mime_value(domain_str)).unwrap();
            }
        } else {
            write!(result, " header.d=unknown").unwrap();
        }

        if let Some(identity_str) = &error.identity_str {
            if let Ok(id) = Identity::from_str(identity_str) {
                format_identity_into_string(result, &id);
            } else {
                write!(result, " header.i={}", format::encode_mime_value(identity_str)).unwrap();
            }
        } else if let Some(d) = valid_domain {
            let id = Identity::from_domain(d);
            format_identity_into_string(result, &id);
        }
    } else {
        write!(result, " header.d=unknown").unwrap();
    }
}

// RFC 8616, section 5 states that internationalised domain names should be in
// Unicode form. See the reference to RFC 6376, section 3.5 and RFC 8601,
// section 2.2.

// Below, encode domain/identity as an RFC 2045 `value`, unless it conforms to
// the production `[[local-part] "@"] domain-name` of RFC 8601, section 2.2, in
// which case quoting must not be applied.

fn format_domain_into_string(result: &mut String, domain: &DomainName) {
    let mut d = domain.as_ref();

    let udomain = domain.to_unicode();

    // Only use conversion if something changed (no trivial case differences).
    if !udomain.eq_ignore_ascii_case(d) {
        d = &udomain;
    }

    let cow;
    if !is_valid_unquoted_pvalue(d) {
        cow = format::encode_mime_value(d);
        d = &cow;
    }

    write!(result, " header.d={d}").unwrap();
}

fn format_identity_into_string(result: &mut String, identity: &Identity) {
    let Identity { local_part, domain } = identity;

    let mut d = domain.as_ref();

    let udomain = domain.to_unicode();

    // Only use conversion if something changed (no trivial case differences).
    if !udomain.eq_ignore_ascii_case(d) {
        d = &udomain;
    }

    let id = match local_part {
        Some(lp) => format!("{lp}@{d}"),
        None => format!("@{d}"),
    };
    let mut id = id.as_str();

    let cow;
    if !is_valid_unquoted_pvalue(id) {
        cow = format::encode_mime_value(id);
        id = &cow;
    }

    write!(result, " header.i={id}").unwrap();
}

fn is_valid_unquoted_pvalue(mut s: &str) -> bool {
    // See RFC 5322, section 3.4.1.
    fn is_local_part(s: &str) -> bool {
        format::is_dot_atom(s) || format::is_quoted_string(s)
    }

    if let Some((l, d)) = s.rsplit_once('@') {
        if !(l.is_empty() || is_local_part(l)) {
            return false;
        }
        s = d;
    }

    // Inputs to this function did have a valid `DomainName`.
    debug_assert!(DomainName::from_str(s).is_ok());

    true
}

fn format_algorithm_into_string(
    result: &mut String,
    signature: Option<&DkimSignature>,
    error: Option<&DkimSignatureError>,
) {
    if let Some(signature) = signature {
        write!(result, " header.a={}", signature.algorithm).unwrap();
    } else if let Some(error) = error {
        if let Some(alg) = &error.algorithm_str {
            write!(result, " header.a={}", format::encode_mime_value(alg)).unwrap();
        }
    }
}

fn format_selector_into_string(
    result: &mut String,
    signature: Option<&DkimSignature>,
    error: Option<&DkimSignatureError>,
) {
    if let Some(signature) = signature {
        write!(result, " header.s={}", signature.selector).unwrap();
    } else if let Some(error) = error {
        if let Some(selector) = &error.selector_str {
            write!(result, " header.s={}", format::encode_mime_value(selector)).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use viadkim::signature::{DkimSignatureErrorKind, Selector, SigningAlgorithm};

    #[test]
    fn format_identities_into_string_sig() {
        let sig = make_signature("XN--B1AGH1AFP.RU", Some("@☕.привет.Ru"));

        let mut s = String::new();
        format_identities_into_string(&mut s, Some(&sig), None);

        assert_eq!(s, " header.d=привет.ru header.i=@☕.привет.Ru");
    }

    #[test]
    fn format_identities_into_string_error() {
        let error = make_signature_error(None, Some("...?"));

        let mut s = String::new();
        format_identities_into_string(&mut s, None, Some(&error));

        assert_eq!(s, " header.d=unknown header.i=\"...?\"");
    }

    fn make_signature(domain: &str, identity: Option<&str>) -> DkimSignature {
        DkimSignature {
            algorithm: SigningAlgorithm::RsaSha256,
            signature_data: Default::default(),
            body_hash: Default::default(),
            canonicalization: Default::default(),
            domain: domain.parse().unwrap(),
            signed_headers: Default::default(),
            identity: identity.map(|id| id.parse().unwrap()),
            selector: Selector::new("ignored").unwrap(),
            body_length: Default::default(),
            timestamp: Default::default(),
            expiration: Default::default(),
            copied_headers: Default::default(),
            ext_tags: Default::default(),
        }
    }

    fn make_signature_error(domain: Option<&str>, identity: Option<&str>) -> DkimSignatureError {
        DkimSignatureError {
            kind: DkimSignatureErrorKind::Utf8Encoding,
            algorithm_str: None,
            signature_data_str: None,
            domain_str: domain.map(Into::into),
            identity_str: identity.map(Into::into),
            selector_str: None,
        }
    }
}
