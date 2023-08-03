use crate::verify;
use std::{error::Error, fmt::Write};
use viadkim::{
    record::DkimKeyRecordError,
    verifier::{DkimAuthResult, VerificationError, VerificationResult, VerificationStatus},
};

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
                VerificationError::BodyHashMismatch => Some("body hash did not verify".into()),
                error => Some(match error.source() {
                    Some(e) => e.to_string(),
                    None => error.to_string(),
                }),
            }
        }
    }
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
