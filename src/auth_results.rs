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
    verifier::{
        DkimAuthResult as DkimResult, VerificationError, VerificationResult, VerificationStatus,
    },
};

// TODO a few things were copied from SPF Milter, think about consolidating later

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

// TODO revisit output formatting; what would be a good format?
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
    let ar = sig.status.to_dkim_auth_result();

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

        // TODO revisit: if an updated viadkim provides the b= string in raw
        // (whitespace not stripped) format, might need to do a bit more work here
        if let Some(s) = prefix {
            write!(result, " header.b={}", format::encode_mime_value(&s)).unwrap();
        }
    }
}

pub fn auth_results_reason_from_status(status: &VerificationStatus) -> Option<String> {
    match status {
        VerificationStatus::Success => None,
        VerificationStatus::Failure(error) => {
            // for now display only the source error
            match error {
                VerificationError::KeyRecordFormat(error) => {
                    // improve key record error message a bit
                    // eg "incompatible version" => "incompatible version in key record" etc.
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

// TODO convert domains to U-form
// TODO is identity displayed properly? see SPF Milter
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

        write!(result, " header.d={}", domain).unwrap();

        if let Some(identity) = &signature.identity {
            write!(result, " header.i={}", identity).unwrap();
        } else {
            let id = Identity::from_domain(domain.clone());
            write!(result, " header.i={}", id).unwrap();
        }
    } else if let Some(error) = error {
        let mut valid_domain = None;

        if let Some(domain_str) = &error.domain_str {
            if let Ok(domain) = DomainName::from_str(domain_str) {
                let d = valid_domain.insert(domain);
                write!(result, " header.d={}", d).unwrap();
            } else {
                write!(result, " header.d={}", format::encode_mime_value(domain_str)).unwrap();
            }
        } else {
            write!(result, " header.d=unknown").unwrap();
        }

        if let Some(identity_str) = &error.identity_str {
            write!(result, " header.i={}", format::encode_mime_value(identity_str)).unwrap();
        } else if let Some(d) = valid_domain {
            let id = Identity::from_domain(d);
            write!(result, " header.i={}", id).unwrap();
        }
    } else {
        write!(result, " header.d=unknown").unwrap();
    }
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
    use viadkim::signature::DkimSignatureErrorKind;

    #[test]
    fn format_identities_into_string_ok() {
        let error = DkimSignatureError {
            kind: DkimSignatureErrorKind::Utf8Encoding,
            algorithm_str: None,
            signature_data_str: None,
            domain_str: None,
            identity_str: Some("...".into()),
            selector_str: None,
        };

        let mut s = String::new();
        format_identities_into_string(&mut s, None, Some(&error));

        assert_eq!(s, " header.d=unknown header.i=...");
    }
}
