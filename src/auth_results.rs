use crate::session;
use std::fmt::Write;
use tracing::debug;
use viadkim::{
    crypto::VerificationError,
    signature::DkimSignatureParseError,
    verifier::{VerificationResult, VerificationStatus, VerifierError},
};

pub enum AuthResultsKind {
    Pass,
    Policy,
    Fail,
    Neutral,
    Permerror,
    Temperror,
}

impl AuthResultsKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Policy => "policy",
            Self::Fail => "fail",
            Self::Neutral => "neutral",
            Self::Permerror => "permerror",
            Self::Temperror => "temperror",
        }
    }
}

// TODO move classification to viadkim?
pub fn auth_results_kind_from_status(status: &VerificationStatus) -> AuthResultsKind {
    use VerifierError::*;

    match status {
        VerificationStatus::Success => AuthResultsKind::Pass,
        VerificationStatus::Failure(error) => match error {
            KeyRecordSyntax
            | DisallowedHashAlgorithm
            | DisallowedServiceType
            | BodyHashMismatch
            | InsufficientBodyLength => AuthResultsKind::Permerror,
            KeyLookup => AuthResultsKind::Temperror,
            DkimSignatureHeaderFormat(error) => match &error.cause {
                DkimSignatureParseError::MissingVersionTag
                | DkimSignatureParseError::HistoricAlgorithm
                | DkimSignatureParseError::MissingAlgorithmTag
                | DkimSignatureParseError::MissingSignatureTag
                | DkimSignatureParseError::MissingBodyHashTag
                | DkimSignatureParseError::InvalidDomain
                | DkimSignatureParseError::MissingDomainTag
                | DkimSignatureParseError::SignedHeadersEmpty
                | DkimSignatureParseError::FromHeaderNotSigned
                | DkimSignatureParseError::MissingSignedHeadersTag
                | DkimSignatureParseError::InvalidBodyLength
                | DkimSignatureParseError::InvalidSelector
                | DkimSignatureParseError::MissingSelectorTag
                | DkimSignatureParseError::InvalidTimestamp
                | DkimSignatureParseError::InvalidExpiration
                | DkimSignatureParseError::DomainMismatch
                | DkimSignatureParseError::InvalidUserId => AuthResultsKind::Permerror,
                DkimSignatureParseError::UnsupportedVersion
                | DkimSignatureParseError::UnsupportedAlgorithm
                | DkimSignatureParseError::UnsupportedCanonicalization
                | DkimSignatureParseError::QueryMethodsNotSupported
                | DkimSignatureParseError::ValueSyntax
                | DkimSignatureParseError::InvalidTagList => AuthResultsKind::Neutral,
            },
            VerificationFailure(error) => match error {
                VerificationError::InvalidKey
                | VerificationError::InsufficientKeySize
                | VerificationError::InvalidSignature => AuthResultsKind::Permerror,
                VerificationError::VerificationFailure => AuthResultsKind::Fail,
            },
        },
    }
}

// TODO
pub fn assemble_auth_results(authserv_id: &str, sigs: Vec<VerificationResult>) -> String {
    let mut result = String::new();

    write!(result, " {}", authserv_id).unwrap();

    for sig in sigs {
        debug!("signature result: {:?}", sig.status);

        result.push_str(";\n\t");

        let ar = auth_results_kind_from_status(&sig.status);

        result.push_str("dkim=");
        result.push_str(ar.as_str());

        write!(
            result,
            " header.d={}",
            session::get_domain_from_verification_result(&sig),
        ).unwrap();

        if let Some(s) = session::get_signature_prefix_from_verification_result(&sig) {
            write!(result, " header.b={s}").unwrap();
        }
    }

    result
}
