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
use viadkim::{
    crypto::{HashAlgorithm, SigningKey},
    header::{FieldName, HeaderFieldError},
    signature::{Canonicalization, CanonicalizationAlgorithm, DomainName, Selector},
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
pub enum OperationMode {
    Sign,
    Verify,
    #[default]
    Auto,
}

impl FromStr for OperationMode {
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
pub enum SignedHeaders {
    Pick(Vec<SignedFieldName>),  // must include From
    PickWithDefault(Vec<SignedFieldName>),  // From stripped (already in default)
    All,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OversignedHeaders {
    Pick(Vec<SignedFieldName>),
    Signed,
    Exhaustive,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Expiration {
    Never,
    After(Duration),  // non-zero
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
            (OversignedHeaders::Exhaustive, SignedHeaders::All) => {
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

    pub fn combine_with(&self, overrides: &PartialSigningConfig) -> Result<Self, Box<dyn Error>> {
        let mut config = self.clone();
        if let Some(default_signed_headers) = &overrides.default_signed_headers {
            config.default_signed_headers = default_signed_headers.clone();
        }
        if let Some(default_unsigned_headers) = &overrides.default_unsigned_headers {
            config.default_unsigned_headers = default_unsigned_headers.clone();
        }
        if let Some(signed_headers) = &overrides.signed_headers {
            config.signed_headers = signed_headers.clone();
        }
        if let Some(oversigned_headers) = &overrides.oversigned_headers {
            config.oversigned_headers = oversigned_headers.clone();
        }
        if let Some(hash_algorithm) = overrides.hash_algorithm {
            config.hash_algorithm = hash_algorithm;
        }
        if let Some(canonicalization) = overrides.canonicalization {
            config.canonicalization = canonicalization;
        }
        if let Some(expire_after) = overrides.expire_after {
            config.expire_after = expire_after;
        }
        if let Some(copy_headers) = overrides.copy_headers {
            config.copy_headers = copy_headers;
        }
        if let Some(limit_body_length) = overrides.limit_body_length {
            config.limit_body_length = limit_body_length;
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
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PartialSigningConfig {
    pub default_signed_headers: Option<Vec<SignedFieldName>>,
    pub default_unsigned_headers: Option<Vec<SignedFieldName>>,
    pub signed_headers: Option<SignedHeaders>,
    pub oversigned_headers: Option<OversignedHeaders>,
    pub hash_algorithm: Option<HashAlgorithm>,
    pub canonicalization: Option<Canonicalization>,
    pub expire_after: Option<Expiration>,
    pub copy_headers: Option<bool>,
    pub limit_body_length: Option<bool>,
}

impl PartialSigningConfig {
    pub fn combine_with(&self, overrides: &PartialSigningConfig) -> Self {
        PartialSigningConfig {
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
        }
    }

    pub fn into_signing_config(self) -> Result<SigningConfig, Box<dyn Error>> {
        let mut config = SigningConfig::default();
        if let Some(default_signed_headers) = self.default_signed_headers {
            config.default_signed_headers = default_signed_headers;
        }
        if let Some(default_unsigned_headers) = self.default_unsigned_headers {
            config.default_unsigned_headers = default_unsigned_headers;
        }
        if let Some(signed_headers) = self.signed_headers {
            config.signed_headers = signed_headers;
        }
        if let Some(oversigned_headers) = self.oversigned_headers {
            config.oversigned_headers = oversigned_headers;
        }
        if let Some(hash_algorithm) = self.hash_algorithm {
            config.hash_algorithm = hash_algorithm;
        }
        if let Some(canonicalization) = self.canonicalization {
            config.canonicalization = canonicalization;
        }
        if let Some(expire_after) = self.expire_after {
            config.expire_after = expire_after;
        }
        if let Some(copy_headers) = self.copy_headers {
            config.copy_headers = copy_headers;
        }
        if let Some(limit_body_length) = self.limit_body_length {
            config.limit_body_length = limit_body_length;
        }

        config.check_invariants()?;

        Ok(config)
    }
}

#[derive(Clone, Debug)]
pub struct OverrideEntry {
    pub expr: Regex,
    pub config: PartialSigningConfig,
}

#[derive(Clone, Debug, Default)]
pub struct SigningOverrides {
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
    pub domain: DomainName,
    pub selector: Selector,
    // TODO no longer "_name"
    pub key_name: Arc<SigningKey>,
    pub signing_config: Option<PartialSigningConfig>,
}
