use crate::session;
use std::fmt::Write;
use tracing::debug;
use viadkim::{
    crypto::VerificationError,
    signature::DkimSignatureErrorKind,
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
    pub fn to_str(&self) -> &'static str {
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
            WrongKeyType
            | KeyRecordSyntax
            | DisallowedHashAlgorithm
            | DisallowedServiceType
            | DomainMismatch
            | InsufficientBodyLength
            | NoKeyFound => AuthResultsKind::Permerror,
            BodyHashMismatch => AuthResultsKind::Fail,
            KeyLookup => AuthResultsKind::Temperror,
            DkimSignatureHeaderFormat(error) => match &error.kind {
                DkimSignatureErrorKind::MissingVersionTag
                | DkimSignatureErrorKind::HistoricAlgorithm
                | DkimSignatureErrorKind::MissingAlgorithmTag
                | DkimSignatureErrorKind::MissingSignatureTag
                | DkimSignatureErrorKind::MissingBodyHashTag
                | DkimSignatureErrorKind::InvalidDomain
                | DkimSignatureErrorKind::MissingDomainTag
                | DkimSignatureErrorKind::SignedHeadersEmpty
                | DkimSignatureErrorKind::FromHeaderNotSigned
                | DkimSignatureErrorKind::MissingSignedHeadersTag
                | DkimSignatureErrorKind::InvalidBodyLength
                | DkimSignatureErrorKind::InvalidSelector
                | DkimSignatureErrorKind::MissingSelectorTag
                | DkimSignatureErrorKind::InvalidTimestamp
                | DkimSignatureErrorKind::InvalidExpiration
                | DkimSignatureErrorKind::DomainMismatch
                | DkimSignatureErrorKind::InvalidUserId => AuthResultsKind::Permerror,
                DkimSignatureErrorKind::UnsupportedVersion
                | DkimSignatureErrorKind::UnsupportedAlgorithm
                | DkimSignatureErrorKind::UnsupportedCanonicalization
                | DkimSignatureErrorKind::QueryMethodsNotSupported
                | DkimSignatureErrorKind::ValueSyntax
                | DkimSignatureErrorKind::InvalidTagList => AuthResultsKind::Neutral,
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

    write!(result, " {authserv_id}").unwrap();

    for sig in sigs {
        debug!("signature result: {:?}", sig.status);

        result.push_str(";\n\t");

        let ar = auth_results_kind_from_status(&sig.status);

        result.push_str("dkim=");
        result.push_str(ar.to_str());

        if let Some(key_size) = sig.key_size {
            result.push_str(" (");
            result.push_str(&key_size.to_string());
            result.push_str("-bit key)");
        }

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
