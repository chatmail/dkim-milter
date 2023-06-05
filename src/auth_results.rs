use crate::verify;
use std::fmt::Write;
use viadkim::verifier::{AuthResultsKind, VerificationResult, VerificationStatus};

pub fn auth_results_reason_from_status(status: &VerificationStatus) -> Option<String> {
    match status {
        VerificationStatus::Success => None,
        VerificationStatus::Failure(error) => Some(error.to_string()),
    }
}

// TODO
pub fn assemble_auth_results(authserv_id: &str, sigs: Vec<VerificationResult>) -> String {
    let mut result = String::new();

    write!(result, " {authserv_id}").unwrap();

    if sigs.is_empty() {
        let ar = AuthResultsKind::None;
        write!(result, "; dkim={ar}").unwrap();
    } else {
        for sig in sigs {
            result.push_str(";\n\t");

            let ar = sig.status.to_auth_results_kind();

            write!(result, "dkim={ar}").unwrap();

            if sig.testing {
                write!(result, " (testing mode)").unwrap();
            }

            if let Some(reason) = auth_results_reason_from_status(&sig.status) {
                write!(result, " reason=\"{reason}\"").unwrap();
            }

            // TODO actually, this doesn't belong in Auth-Results
            // if let Some(key_size) = sig.key_size {
            //     write!(result, " ({}-bit key)", key_size.to_string()).unwrap();
            // }

            write!(
                result,
                " header.d={}",
                verify::get_domain_from_verification_result(&sig),
            ).unwrap();

            if let Some(s) = verify::get_signature_prefix_from_verification_result(&sig) {
                write!(result, " header.b={s}").unwrap();
            }
        }
    }

    result
}
