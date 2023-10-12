use crate::session::DomainExpr;
use ipnet::IpNet;
use regex::Regex;
use std::{
    collections::HashSet,
    error::Error,
    fmt::{self, Debug, Display, Formatter},
    net::IpAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use syslog::Facility;
use viadkim::{
    crypto::{HashAlgorithm, SigningKey},
    header::{FieldName, HeaderFieldError},
    signature::{Canonicalization, CanonicalizationAlgorithm, Selector},
    signer,
};

// Provide FromStr impl only for types that have an ‘atomic’, ‘natural’, obvious
// string representation.

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseLogDestinationError;

impl Error for ParseLogDestinationError {}

impl Display for ParseLogDestinationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse log destination")
    }
}

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

impl Error for ParseLogLevelError {}

impl Display for ParseLogLevelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse log level")
    }
}

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

impl Error for ParseSyslogFacilityError {}

impl Display for ParseSyslogFacilityError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse syslog facility")
    }
}

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

impl Error for ParseSocketError {}

impl Display for ParseSocketError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse socket")
    }
}

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
        self.trust_loopback && addr.is_loopback() || self.networks.iter().any(|n| n.contains(&addr))
    }

    pub fn contains_loopback(&self) -> bool {
        // TODO pedantically, loopback could also be present as literals in self.networks
        self.trust_loopback
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Expiration {
    Never,
    After(Duration),  // non-zero
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RejectFailure {
    Missing,
    Failing,
    AuthorMismatch,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RejectFailures(pub HashSet<RejectFailure>);

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
    pub default_signed_headers: Vec<SignedFieldName>,  // must include From
    pub default_unsigned_headers: Vec<SignedFieldName>,  // must not include From
    pub signed_headers: SignedHeaders,
    pub oversigned_headers: OversignedHeaders,
    pub hash_algorithm: HashAlgorithm,
    pub canonicalization: Canonicalization,
    pub expire_after: Expiration,
    pub copy_headers: bool,
    pub limit_body_length: bool,
    pub request_reports: bool,
}

impl SigningConfig {
    fn check_invariants(&self) -> Result<(), Box<dyn Error>> {
        match (&self.oversigned_headers, &self.signed_headers) {
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

        if let Some(value) = &overrides.default_signed_headers {
            config.default_signed_headers = value.as_ref().clone();
        }
        if let Some(value) = &overrides.default_unsigned_headers {
            config.default_unsigned_headers = value.as_ref().clone();
        }
        if let Some(value) = &overrides.signed_headers {
            config.signed_headers = value.as_ref().clone();
        }
        if let Some(value) = &overrides.oversigned_headers {
            config.oversigned_headers = value.as_ref().clone();
        }
        if let Some(value) = overrides.hash_algorithm {
            config.hash_algorithm = value;
        }
        if let Some(value) = overrides.canonicalization {
            config.canonicalization = value;
        }
        if let Some(value) = overrides.expire_after {
            config.expire_after = value;
        }
        if let Some(value) = overrides.copy_headers {
            config.copy_headers = value;
        }
        if let Some(value) = overrides.limit_body_length {
            config.limit_body_length = value;
        }
        if let Some(value) = overrides.request_reports {
            config.request_reports = value;
        }

        config.check_invariants()?;

        Ok(config)
    }
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            default_signed_headers: signer::default_signed_headers().into_iter()
                .map(SignedFieldName)
                .collect(),
            default_unsigned_headers: signer::default_unsigned_headers().into_iter()
                .map(SignedFieldName)
                .collect(),
            signed_headers: SignedHeaders::PickWithDefault(Default::default()),
            oversigned_headers: OversignedHeaders::Pick(Default::default()),
            hash_algorithm: HashAlgorithm::Sha256,
            canonicalization: Canonicalization {
                header: CanonicalizationAlgorithm::Relaxed,
                body: CanonicalizationAlgorithm::Simple,
            },
            expire_after: Expiration::After(Duration::from_secs(60 * 60 * 24 * 5)),  // five days
            copy_headers: false,
            limit_body_length: false,
            request_reports: false,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PartialSigningConfig {
    pub default_signed_headers: Option<Arc<Vec<SignedFieldName>>>,
    pub default_unsigned_headers: Option<Arc<Vec<SignedFieldName>>>,
    pub signed_headers: Option<Arc<SignedHeaders>>,
    pub oversigned_headers: Option<Arc<OversignedHeaders>>,
    pub hash_algorithm: Option<HashAlgorithm>,
    pub canonicalization: Option<Canonicalization>,
    pub expire_after: Option<Expiration>,
    pub copy_headers: Option<bool>,
    pub limit_body_length: Option<bool>,
    pub request_reports: Option<bool>,
}

impl PartialSigningConfig {
    pub fn merged_with(&self, overrides: &Self) -> Self {
        Self {
            default_signed_headers: overrides.default_signed_headers.as_ref()
                .or(self.default_signed_headers.as_ref())
                .cloned(),
            default_unsigned_headers: overrides.default_unsigned_headers.as_ref()
                .or(self.default_unsigned_headers.as_ref())
                .cloned(),
            signed_headers: overrides.signed_headers.as_ref()
                .or(self.signed_headers.as_ref())
                .cloned(),
            oversigned_headers: overrides.oversigned_headers.as_ref()
                .or(self.oversigned_headers.as_ref())
                .cloned(),
            hash_algorithm: overrides.hash_algorithm.or(self.hash_algorithm),
            canonicalization: overrides.canonicalization.or(self.canonicalization),
            expire_after: overrides.expire_after.or(self.expire_after),
            copy_headers: overrides.copy_headers.or(self.copy_headers),
            limit_body_length: overrides.limit_body_length.or(self.limit_body_length),
            request_reports: overrides.request_reports.or(self.request_reports),
        }
    }

    pub fn merge(&mut self, other: &Self) {
        if let Some(value) = &other.default_signed_headers {
            self.default_signed_headers = Some(value.clone());
        }
        if let Some(value) = &other.default_unsigned_headers {
            self.default_unsigned_headers = Some(value.clone());
        }
        if let Some(value) = &other.signed_headers {
            self.signed_headers = Some(value.clone());
        }
        if let Some(value) = &other.oversigned_headers {
            self.oversigned_headers = Some(value.clone());
        }
        if let Some(value) = other.hash_algorithm {
            self.hash_algorithm = Some(value);
        }
        if let Some(value) = other.canonicalization {
            self.canonicalization = Some(value);
        }
        if let Some(value) = other.expire_after {
            self.expire_after = Some(value);
        }
        if let Some(value) = other.copy_headers {
            self.copy_headers = Some(value);
        }
        if let Some(value) = other.limit_body_length {
            self.limit_body_length = Some(value);
        }
        if let Some(value) = other.request_reports {
            self.request_reports = Some(value);
        }
    }

    pub fn into_signing_config(self) -> Result<SigningConfig, Box<dyn Error>> {
        let mut config = SigningConfig::default();

        if let Some(value) = self.default_signed_headers {
            config.default_signed_headers = unwrap_arc(value);
        }
        if let Some(value) = self.default_unsigned_headers {
            config.default_unsigned_headers = unwrap_arc(value);
        }
        if let Some(value) = self.signed_headers {
            config.signed_headers = unwrap_arc(value);
        }
        if let Some(value) = self.oversigned_headers {
            config.oversigned_headers = unwrap_arc(value);
        }
        if let Some(value) = self.hash_algorithm {
            config.hash_algorithm = value;
        }
        if let Some(value) = self.canonicalization {
            config.canonicalization = value;
        }
        if let Some(value) = self.expire_after {
            config.expire_after = value;
        }
        if let Some(value) = self.copy_headers {
            config.copy_headers = value;
        }
        if let Some(value) = self.limit_body_length {
            config.limit_body_length = value;
        }
        if let Some(value) = self.request_reports {
            config.request_reports = value;
        }

        config.check_invariants()?;

        Ok(config)
    }
}

#[derive(Clone, Debug)]
pub struct OverrideNetworkEntry {
    pub net: IpNet,
    pub config: ConfigOverrides,
}

#[derive(Clone, Debug)]
pub struct OverrideEntry {
    pub expr: Regex,
    pub config: ConfigOverrides,
}

#[derive(Clone, Debug, Default)]
pub struct OverrideEntries {
    pub entries: Vec<OverrideEntry>,
}

// TODO
#[derive(Clone, Debug, Default)]
pub struct SigningSenders {
    pub entries: Vec<SenderEntry>,
}

#[derive(Clone, Debug)]
pub struct SenderEntry {
    pub sender_expr: Regex,
    pub domain: DomainExpr,
    pub selector: Selector,
    // TODO no longer "_name"
    pub key_name: Arc<SigningKey>,
    pub signing_config: Option<PartialSigningConfig>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationConfig {
    pub allow_expired: bool,
    pub allow_sha1: bool,
    pub allow_timestamp_in_future: bool,
    pub forbid_unsigned_content: bool,
    pub max_signatures: usize,
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
        if let Some(value) = overrides.max_signatures {
            config.max_signatures = value;
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
            max_signatures: 10,
            min_rsa_key_bits: 1024,
            reject_failures: Default::default(),
            required_signed_headers:
                vec![SignedFieldNameWithQualifier::Asterisk(SignedFieldName::new("From").unwrap())],
            time_tolerance: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PartialVerificationConfig {
    pub allow_expired: Option<bool>,
    pub allow_sha1: Option<bool>,
    pub allow_timestamp_in_future: Option<bool>,
    pub forbid_unsigned_content: Option<bool>,
    pub max_signatures: Option<usize>,
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
            max_signatures: overrides.max_signatures.or(self.max_signatures),
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
        if let Some(value) = other.max_signatures {
            self.max_signatures = Some(value);
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
        if let Some(value) = self.max_signatures {
            config.max_signatures = value;
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
