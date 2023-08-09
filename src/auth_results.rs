use crate::{format, verify};
use std::{borrow::Cow, error::Error, fmt::Write, str};
use viadkim::{
    record::DkimKeyRecordError,
    verifier::{DkimAuthResult, VerificationError, VerificationResult, VerificationStatus},
};

// TODO a few things were copied from SPF Milter, think about consolidating later

pub fn extract_authserv_id(value: &[u8]) -> Option<Cow<'_, str>> {
    // *authserv-id* is a lexical token of kind `value` as defined in RFC 2045,
    // section 5.1, that is, either a `token` or a quoted string. Immediately
    // before the *authserv-id* there may be a CFWS.
    let value = format::strip_cfws(value).unwrap_or(value);

    if let Some(rest) = format::strip_mime_value(value) {
        // Directly after the *authserv-id* may come either a semicolon or
        // another CFWS. Validation proceeds no further than this.
        if rest.starts_with(b";") || format::strip_cfws(rest).is_some() {
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

// TODO revisit output format; what would be a good format?
pub fn assemble_auth_results(authserv_id: &str, sigs: Vec<VerificationResult>) -> String {
    let mut result = String::new();

    write!(result, " {authserv_id}").unwrap();

    if sigs.is_empty() {
        let ar = DkimAuthResult::None;
        write!(result, "; dkim={ar}").unwrap();
    } else {
        for sig in sigs {
            result.push_str(";\n\t");

            let ar = sig.status.to_dkim_auth_result();

            // TODO safely encode all MIME values

            write!(result, "dkim={ar}").unwrap();

            if sig.key_record.as_ref().map_or(false, |r| r.is_testing_mode()) {
                write!(result, " (test mode)").unwrap();
            }

            if let Some(reason) = auth_results_reason_from_status(&sig.status) {
                write!(result, " reason=\"{reason}\"").unwrap();
            }

            write!(
                result,
                " header.d={}",
                verify::get_domain_from_verification_result(&sig),
            ).unwrap();

            if let Some(signature) = &sig.signature {
                if let Some(identity) = &signature.identity {
                    write!(result, " header.i={identity}").unwrap();
                }
            }

            result.push_str("\n\t");

            if let Some(signature) = &sig.signature {
                write!(result, " header.a={}", signature.algorithm).unwrap();
            } else if let VerificationStatus::Failure(VerificationError::DkimSignatureFormat(error)) = &sig.status {
                if let Some(alg) = &error.algorithm {
                    write!(result, " header.a={alg}").unwrap();
                }
            }

            if let Some(signature) = &sig.signature {
                write!(result, " header.s={}", signature.selector).unwrap();
            }

            if let Some(s) = verify::get_signature_prefix_from_verification_result(&sig) {
                write!(result, " header.b={s}").unwrap();
            }
        }
    }

    result
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
                // TODO drop this mapping once an updated viadkim is available
                VerificationError::BodyHashMismatch => Some("body hash did not verify".into()),
                error => Some(match error.source() {
                    Some(e) => e.to_string(),
                    None => error.to_string(),
                }),
            }
        }
    }
}
