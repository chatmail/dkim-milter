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

use ipnet::IpNet;
use std::{
    collections::HashSet,
    error::Error,
    fmt::{self, Debug, Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use syslog::Facility;
use viadkim::{
    crypto::HashAlgorithm,
    header::{FieldName, HeaderFieldError},
    signature::{Canonicalization, CanonicalizationAlgorithm, DomainName},
    signer::{self, Expiration},
};

// Provide FromStr impl only for types that have an ‘atomic’, ‘natural’, obvious
// string representation.

#[derive(Clone, Debug, Default)]
pub struct ConfigOverrides {
    pub signing_config: PartialSigningConfig,
    pub verification_config: PartialVerificationConfig,
}

impl ConfigOverrides {
    pub fn merge(&mut self, other: &Self) {
        self.signing_config.merge(&other.signing_config);
        self.verification_config.merge(&other.verification_config);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SigningConfig {
    pub ascii_only_signatures: bool,
    pub canonicalization: Canonicalization,
    pub copy_headers: bool,
    pub default_signed_headers: Vec<SignedFieldName>,  // must include From
    pub default_unsigned_headers: Vec<SignedFieldName>,  // must not include From
    pub expiration: Expiration,
    pub hash_algorithm: HashAlgorithm,
    pub limit_body_length: bool,
    pub oversign_headers: OversignedHeaders,
    pub request_reports: bool,
    pub sign_headers: SignedHeaders,
}

impl SigningConfig {
    fn check_invariants(&self) -> Result<(), Box<dyn Error>> {
        match (&self.oversign_headers, &self.sign_headers) {
            (
                OversignedHeaders::Pick(oversigned_names),
                s @ (SignedHeaders::Pick(names) | SignedHeaders::PickWithDefault(names)),
            ) => {
                let mut all_signed: HashSet<_> = names.iter().collect();
                if matches!(s, SignedHeaders::PickWithDefault(_)) {
                    all_signed.extend(self.default_signed_headers.iter());
                }
                for h in oversigned_names {
                    if !all_signed.contains(h) {
                        return Err("cannot oversign header not included for signing".into());
                    }
                }
            }
            (OversignedHeaders::Pick(oversigned_names), SignedHeaders::All) => {
                for h in oversigned_names {
                    if self.default_unsigned_headers.contains(h) {
                        return Err("cannot oversign header expressly excluded from signing".into());
                    }
                }
            }
            (OversignedHeaders::Extended, SignedHeaders::All) => {
                for h in &self.default_signed_headers {
                    if self.default_unsigned_headers.contains(h) {
                        return Err("cannot oversign header expressly excluded from signing".into());
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn merged_with(&self, overrides: &PartialSigningConfig) -> Result<Self, Box<dyn Error>> {
        let mut config = self.clone();

        if let Some(value) = overrides.ascii_only_signatures {
            config.ascii_only_signatures = value;
        }
        if let Some(value) = overrides.canonicalization {
            config.canonicalization = value;
        }
        if let Some(value) = overrides.copy_headers {
            config.copy_headers = value;
        }
        if let Some(value) = &overrides.default_signed_headers {
            config.default_signed_headers = value.as_ref().clone();
        }
        if let Some(value) = &overrides.default_unsigned_headers {
            config.default_unsigned_headers = value.as_ref().clone();
        }
        if let Some(value) = overrides.expiration {
            config.expiration = value;
        }
        if let Some(value) = overrides.hash_algorithm {
            config.hash_algorithm = value;
        }
        if let Some(value) = overrides.limit_body_length {
            config.limit_body_length = value;
        }
        if let Some(value) = &overrides.oversign_headers {
            config.oversign_headers = value.as_ref().clone();
        }
        if let Some(value) = overrides.request_reports {
            config.request_reports = value;
        }
        if let Some(value) = &overrides.sign_headers {
            config.sign_headers = value.as_ref().clone();
        }

        config.check_invariants()?;

        Ok(config)
    }
}

impl Default for SigningConfig {
    fn default() -> Self {
        use CanonicalizationAlgorithm::*;
        Self {
            ascii_only_signatures: false,
            canonicalization: Canonicalization::from((Relaxed, Simple)),
            copy_headers: false,
            default_signed_headers: signer::default_signed_headers().into_iter()
                .map(SignedFieldName)
                .collect(),
            default_unsigned_headers: signer::default_unsigned_headers().into_iter()
                .map(SignedFieldName)
                .collect(),
            expiration: Expiration::After(Duration::from_secs(60 * 60 * 24 * 5)),  // five days
            hash_algorithm: HashAlgorithm::Sha256,
            limit_body_length: false,
            oversign_headers: OversignedHeaders::Pick(Default::default()),
            request_reports: false,
            sign_headers: SignedHeaders::PickWithDefault(Default::default()),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PartialSigningConfig {
    pub ascii_only_signatures: Option<bool>,
    pub canonicalization: Option<Canonicalization>,
    pub copy_headers: Option<bool>,
    pub default_signed_headers: Option<Arc<Vec<SignedFieldName>>>,
    pub default_unsigned_headers: Option<Arc<Vec<SignedFieldName>>>,
    pub expiration: Option<Expiration>,
    pub hash_algorithm: Option<HashAlgorithm>,
    pub limit_body_length: Option<bool>,
    pub oversign_headers: Option<Arc<OversignedHeaders>>,
    pub request_reports: Option<bool>,
    pub sign_headers: Option<Arc<SignedHeaders>>,
}

impl PartialSigningConfig {
    pub fn merged_with(&self, overrides: &Self) -> Self {
        Self {
            ascii_only_signatures: overrides.ascii_only_signatures.or(self.ascii_only_signatures),
            canonicalization: overrides.canonicalization.or(self.canonicalization),
            copy_headers: overrides.copy_headers.or(self.copy_headers),
            default_signed_headers: overrides.default_signed_headers.as_ref()
                .or(self.default_signed_headers.as_ref())
                .cloned(),
            default_unsigned_headers: overrides.default_unsigned_headers.as_ref()
                .or(self.default_unsigned_headers.as_ref())
                .cloned(),
            expiration: overrides.expiration.or(self.expiration),
            hash_algorithm: overrides.hash_algorithm.or(self.hash_algorithm),
            limit_body_length: overrides.limit_body_length.or(self.limit_body_length),
            oversign_headers: overrides.oversign_headers.as_ref()
                .or(self.oversign_headers.as_ref())
                .cloned(),
            request_reports: overrides.request_reports.or(self.request_reports),
            sign_headers: overrides.sign_headers.as_ref()
                .or(self.sign_headers.as_ref())
                .cloned(),
        }
    }

    pub fn merge(&mut self, other: &Self) {
        if let Some(value) = other.ascii_only_signatures {
            self.ascii_only_signatures = Some(value);
        }
        if let Some(value) = other.canonicalization {
            self.canonicalization = Some(value);
        }
        if let Some(value) = other.copy_headers {
            self.copy_headers = Some(value);
        }
        if let Some(value) = &other.default_signed_headers {
            self.default_signed_headers = Some(value.clone());
        }
        if let Some(value) = &other.default_unsigned_headers {
            self.default_unsigned_headers = Some(value.clone());
        }
        if let Some(value) = other.expiration {
            self.expiration = Some(value);
        }
        if let Some(value) = other.hash_algorithm {
            self.hash_algorithm = Some(value);
        }
        if let Some(value) = other.limit_body_length {
            self.limit_body_length = Some(value);
        }
        if let Some(value) = &other.oversign_headers {
            self.oversign_headers = Some(value.clone());
        }
        if let Some(value) = other.request_reports {
            self.request_reports = Some(value);
        }
        if let Some(value) = &other.sign_headers {
            self.sign_headers = Some(value.clone());
        }
    }

    pub fn into_signing_config(self) -> Result<SigningConfig, Box<dyn Error>> {
        let mut config = SigningConfig::default();

        if let Some(value) = self.ascii_only_signatures {
            config.ascii_only_signatures = value;
        }
        if let Some(value) = self.canonicalization {
            config.canonicalization = value;
        }
        if let Some(value) = self.copy_headers {
            config.copy_headers = value;
        }
        if let Some(value) = self.default_signed_headers {
            config.default_signed_headers = unwrap_arc(value);
        }
        if let Some(value) = self.default_unsigned_headers {
            config.default_unsigned_headers = unwrap_arc(value);
        }
        if let Some(value) = self.expiration {
            config.expiration = value;
        }
        if let Some(value) = self.hash_algorithm {
            config.hash_algorithm = value;
        }
        if let Some(value) = self.limit_body_length {
            config.limit_body_length = value;
        }
        if let Some(value) = self.oversign_headers {
            config.oversign_headers = unwrap_arc(value);
        }
        if let Some(value) = self.request_reports {
            config.request_reports = value;
        }
        if let Some(value) = self.sign_headers {
            config.sign_headers = unwrap_arc(value);
        }

        config.check_invariants()?;

        Ok(config)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationConfig {
    pub allow_expired: bool,
    pub allow_sha1: bool,
    pub allow_timestamp_in_future: bool,
    pub forbid_unsigned_content: bool,
    pub max_signatures_to_verify: usize,
    pub min_rsa_key_bits: usize,
    pub reject_failures: RejectFailures,
    pub required_signed_headers: Vec<SignedFieldNameWithQualifier>,
    pub time_tolerance: Duration,
}

impl VerificationConfig {
    pub fn merged_with(&self, overrides: &PartialVerificationConfig) -> Self {
        let mut config = self.clone();

        if let Some(value) = overrides.allow_expired {
            config.allow_expired = value;
        }
        if let Some(value) = overrides.allow_sha1 {
            config.allow_sha1 = value;
        }
        if let Some(value) = overrides.allow_timestamp_in_future {
            config.allow_timestamp_in_future = value;
        }
        if let Some(value) = overrides.forbid_unsigned_content {
            config.forbid_unsigned_content = value;
        }
        if let Some(value) = overrides.max_signatures_to_verify {
            config.max_signatures_to_verify = value;
        }
        if let Some(value) = overrides.min_rsa_key_bits {
            config.min_rsa_key_bits = value;
        }
        if let Some(value) = &overrides.reject_failures {
            config.reject_failures = value.as_ref().clone();
        }
        if let Some(value) = &overrides.required_signed_headers {
            config.required_signed_headers = value.as_ref().clone();
        }
        if let Some(value) = overrides.time_tolerance {
            config.time_tolerance = value;
        }

        config
    }
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            allow_expired: false,
            allow_sha1: false,
            allow_timestamp_in_future: false,
            forbid_unsigned_content: false,
            max_signatures_to_verify: 10,
            min_rsa_key_bits: 1024,
            reject_failures: Default::default(),
            required_signed_headers: vec![SignedFieldNameWithQualifier::Asterisk(
                SignedFieldName::new("From").unwrap(),
            )],
            time_tolerance: Duration::from_secs(5 * 60),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PartialVerificationConfig {
    pub allow_expired: Option<bool>,
    pub allow_sha1: Option<bool>,
    pub allow_timestamp_in_future: Option<bool>,
    pub forbid_unsigned_content: Option<bool>,
    pub max_signatures_to_verify: Option<usize>,
    pub min_rsa_key_bits: Option<usize>,
    pub reject_failures: Option<Arc<RejectFailures>>,
    pub required_signed_headers: Option<Arc<Vec<SignedFieldNameWithQualifier>>>,
    pub time_tolerance: Option<Duration>,
}

impl PartialVerificationConfig {
    pub fn merged_with(&self, overrides: &Self) -> Self {
        Self {
            allow_expired: overrides.allow_expired.or(self.allow_expired),
            allow_sha1: overrides.allow_sha1.or(self.allow_sha1),
            allow_timestamp_in_future: overrides.allow_timestamp_in_future.or(self.allow_timestamp_in_future),
            forbid_unsigned_content: overrides.forbid_unsigned_content.or(self.forbid_unsigned_content),
            max_signatures_to_verify: overrides.max_signatures_to_verify.or(self.max_signatures_to_verify),
            min_rsa_key_bits: overrides.min_rsa_key_bits.or(self.min_rsa_key_bits),
            reject_failures: overrides.reject_failures.as_ref()
                .or(self.reject_failures.as_ref())
                .cloned(),
            required_signed_headers: overrides.required_signed_headers.as_ref()
                .or(self.required_signed_headers.as_ref())
                .cloned(),
            time_tolerance: overrides.time_tolerance.or(self.time_tolerance),
        }
    }

    pub fn merge(&mut self, other: &Self) {
        if let Some(value) = other.allow_expired {
            self.allow_expired = Some(value);
        }
        if let Some(value) = other.allow_sha1 {
            self.allow_sha1 = Some(value);
        }
        if let Some(value) = other.allow_timestamp_in_future {
            self.allow_timestamp_in_future = Some(value);
        }
        if let Some(value) = other.forbid_unsigned_content {
            self.forbid_unsigned_content = Some(value);
        }
        if let Some(value) = other.max_signatures_to_verify {
            self.max_signatures_to_verify = Some(value);
        }
        if let Some(value) = other.min_rsa_key_bits {
            self.min_rsa_key_bits = Some(value);
        }
        if let Some(value) = &other.reject_failures {
            self.reject_failures = Some(value.clone());
        }
        if let Some(value) = &other.required_signed_headers {
            self.required_signed_headers = Some(value.clone());
        }
        if let Some(value) = other.time_tolerance {
            self.time_tolerance = Some(value);
        }
    }

    pub fn into_verification_config(self) -> VerificationConfig {
        let mut config = VerificationConfig::default();

        if let Some(value) = self.allow_expired {
            config.allow_expired = value;
        }
        if let Some(value) = self.allow_sha1 {
            config.allow_sha1 = value;
        }
        if let Some(value) = self.allow_timestamp_in_future {
            config.allow_timestamp_in_future = value;
        }
        if let Some(value) = self.forbid_unsigned_content {
            config.forbid_unsigned_content = value;
        }
        if let Some(value) = self.max_signatures_to_verify {
            config.max_signatures_to_verify = value;
        }
        if let Some(value) = self.min_rsa_key_bits {
            config.min_rsa_key_bits = value;
        }
        if let Some(value) = self.reject_failures {
            config.reject_failures = unwrap_arc(value);
        }
        if let Some(value) = self.required_signed_headers {
            config.required_signed_headers = unwrap_arc(value);
        }
        if let Some(value) = self.time_tolerance {
            config.time_tolerance = value;
        }

        config
    }
}

fn unwrap_arc<T: Clone>(arc: Arc<T>) -> T {
    Arc::try_unwrap(arc).unwrap_or_else(|a| a.as_ref().clone())
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseLogDestinationError;

impl Display for ParseLogDestinationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse log destination")
    }
}

impl Error for ParseLogDestinationError {}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum LogDestination {
    #[default]
    Syslog,
    Stderr,
}

impl FromStr for LogDestination {
    type Err = ParseLogDestinationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "syslog" => Ok(Self::Syslog),
            "stderr" => Ok(Self::Stderr),
            _ => Err(ParseLogDestinationError),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseLogLevelError;

impl Display for ParseLogLevelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse log level")
    }
}

impl Error for ParseLogLevelError {}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}

impl FromStr for LogLevel {
    type Err = ParseLogLevelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            _ => Err(ParseLogLevelError),
        }
    }
}

/// An error indicating that a syslog facility could not be parsed.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseSyslogFacilityError;

impl Display for ParseSyslogFacilityError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse syslog facility")
    }
}

impl Error for ParseSyslogFacilityError {}

/// The syslog facility.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum SyslogFacility {
    Auth,
    Authpriv,
    Cron,
    Daemon,
    Ftp,
    Kern,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
    Lpr,
    #[default]
    Mail,
    News,
    Syslog,
    User,
    Uucp,
}

impl FromStr for SyslogFacility {
    type Err = ParseSyslogFacilityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auth" => Ok(Self::Auth),
            "authpriv" => Ok(Self::Authpriv),
            "cron" => Ok(Self::Cron),
            "daemon" => Ok(Self::Daemon),
            "ftp" => Ok(Self::Ftp),
            "kern" => Ok(Self::Kern),
            "local0" => Ok(Self::Local0),
            "local1" => Ok(Self::Local1),
            "local2" => Ok(Self::Local2),
            "local3" => Ok(Self::Local3),
            "local4" => Ok(Self::Local4),
            "local5" => Ok(Self::Local5),
            "local6" => Ok(Self::Local6),
            "local7" => Ok(Self::Local7),
            "lpr" => Ok(Self::Lpr),
            "mail" => Ok(Self::Mail),
            "news" => Ok(Self::News),
            "syslog" => Ok(Self::Syslog),
            "user" => Ok(Self::User),
            "uucp" => Ok(Self::Uucp),
            _ => Err(ParseSyslogFacilityError),
        }
    }
}

impl From<SyslogFacility> for Facility {
    fn from(syslog_facility: SyslogFacility) -> Self {
        match syslog_facility {
            SyslogFacility::Auth => Self::LOG_AUTH,
            SyslogFacility::Authpriv => Self::LOG_AUTHPRIV,
            SyslogFacility::Cron => Self::LOG_CRON,
            SyslogFacility::Daemon => Self::LOG_DAEMON,
            SyslogFacility::Ftp => Self::LOG_FTP,
            SyslogFacility::Kern => Self::LOG_KERN,
            SyslogFacility::Local0 => Self::LOG_LOCAL0,
            SyslogFacility::Local1 => Self::LOG_LOCAL1,
            SyslogFacility::Local2 => Self::LOG_LOCAL2,
            SyslogFacility::Local3 => Self::LOG_LOCAL3,
            SyslogFacility::Local4 => Self::LOG_LOCAL4,
            SyslogFacility::Local5 => Self::LOG_LOCAL5,
            SyslogFacility::Local6 => Self::LOG_LOCAL6,
            SyslogFacility::Local7 => Self::LOG_LOCAL7,
            SyslogFacility::Lpr => Self::LOG_LPR,
            SyslogFacility::Mail => Self::LOG_MAIL,
            SyslogFacility::News => Self::LOG_NEWS,
            SyslogFacility::Syslog => Self::LOG_SYSLOG,
            SyslogFacility::User => Self::LOG_USER,
            SyslogFacility::Uucp => Self::LOG_UUCP,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseSocketError;

impl Display for ParseSocketError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse socket")
    }
}

impl Error for ParseSocketError {}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Socket {
    Inet(String),
    Unix(String),
}

impl Display for Socket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet(s) => write!(f, "inet:{s}"),
            Self::Unix(s) => write!(f, "unix:{s}"),
        }
    }
}

impl FromStr for Socket {
    type Err = ParseSocketError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(s) = s.strip_prefix("inet:") {
            Ok(Self::Inet(s.into()))
        } else if let Some(s) = s.strip_prefix("unix:") {
            Ok(Self::Unix(s.into()))
        } else {
            Err(ParseSocketError)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum OpMode {
    Sign,
    Verify,
    #[default]
    Auto,
}

impl FromStr for OpMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sign" => Ok(Self::Sign),
            "verify" => Ok(Self::Verify),
            "auto" => Ok(Self::Auto),
            _ => Err("unknown mode"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedNetworks {
    pub trust_loopback: bool,
    pub networks: HashSet<IpNet>,
}

impl TrustedNetworks {
    pub fn contains(&self, addr: IpAddr) -> bool {
        (self.trust_loopback && addr.is_loopback())
            || self.networks.iter().any(|n| n.contains(&addr))
    }

    pub fn contains_loopback(&self) -> bool {
        // Also do a rudimentary check if a well-known loopback address is
        // contained in `self.networks`.
        self.trust_loopback
            || self.networks.iter().any(|n| {
                n.contains(&IpAddr::from(Ipv4Addr::LOCALHOST))
                    || n.contains(&IpAddr::from(Ipv6Addr::LOCALHOST))
            })
    }
}

impl Default for TrustedNetworks {
    fn default() -> Self {
        Self {
            trust_loopback: true,
            networks: Default::default(),
        }
    }
}

// like viadkim's FieldName but does not allow ";" in name
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SignedFieldName(FieldName);

impl SignedFieldName {
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, HeaderFieldError> {
        let name = FieldName::new(value)?;
        if name.as_ref().contains(';') {
            return Err(HeaderFieldError);
        }
        Ok(Self(name))
    }
}

impl AsRef<FieldName> for SignedFieldName {
    fn as_ref(&self) -> &FieldName {
        &self.0
    }
}

impl fmt::Debug for SignedFieldName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SignedFieldNameWithQualifier {
    Bare(SignedFieldName),
    Plus(SignedFieldName),
    Asterisk(SignedFieldName),
}

#[derive(Clone, Debug, PartialEq)]
pub enum SignedHeaders {
    Pick(Vec<SignedFieldName>),  // must include From
    PickWithDefault(Vec<SignedFieldName>),  // From stripped (already in default)
    All,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OversignedHeaders {
    Pick(Vec<SignedFieldName>),
    Signed,
    Extended,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RejectFailure {
    Missing,
    NoPass,
    AuthorMismatch,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RejectFailures(pub HashSet<RejectFailure>);

#[derive(Clone, Debug)]
pub enum DomainExpr {
    Domain(DomainName),
    SenderDomain,
    Identity(IdentityExpr),
}

#[derive(Clone, Debug)]
pub struct IdentityExpr {
    pub local_part: Option<LocalPartExpr>,
    pub domain_part: IdentityDomainExpr,
}

#[derive(Clone, Debug)]
pub enum LocalPartExpr {
    LocalPart(String),
    SenderLocalPart,
}

#[derive(Clone, Debug)]
pub enum IdentityDomainExpr {
    Domain(DomainName),
    SenderDomain,
    SplitDomain {
        d_domain: DomainName,
        i_domain: DomainName,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv4Net;

    #[test]
    fn trusted_networks_contains_ip() {
        let net = Ipv4Net::new([43, 5, 0, 0].into(), 16).unwrap();
        let trusted_networks = TrustedNetworks {
            networks: HashSet::from([net.into()]),
            ..Default::default()
        };

        assert!(trusted_networks.contains(IpAddr::from([43, 5, 117, 8])));
        assert!(trusted_networks.contains(IpAddr::from(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn trusted_networks_contains_loopback() {
        let trusted_networks = TrustedNetworks::default();

        assert!(trusted_networks.contains_loopback());

        let net = Ipv4Net::new([127, 0, 0, 1].into(), 8).unwrap();
        let trusted_networks = TrustedNetworks {
            trust_loopback: false,
            networks: HashSet::from([net.into()]),
        };

        assert!(trusted_networks.contains_loopback());
    }
}
