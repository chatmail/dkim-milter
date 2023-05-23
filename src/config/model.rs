use regex::Regex;
use std::{
    error::Error,
    fmt::{self, Debug, Display, Formatter},
    num::{NonZeroU32, ParseIntError},
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
    /*
    #[default]
    Journald,
    */
    #[default]
    Syslog,
    Stderr,
}

impl FromStr for LogDestination {
    type Err = ParseLogDestinationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            /*
            "journald" => Ok(Self::Journald),
            */
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
    #[default]
    Auto,  // sign if matching signing senders, verify otherwise
    Verify,  // always verify, no signing
    Sign,  // sign if matching signing senders, no verifying
}

impl FromStr for OperationMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "verify" => Ok(Self::Verify),
            "sign" => Ok(Self::Sign),
            _ => Err("unknown mode"),
        }
    }
}

// TODO read log config, before other config (config reading requires logging)
#[derive(Clone, Debug)]
pub struct LogConfig {
    pub log_destination: LogDestination,
    pub log_level: LogLevel,
}

// like viadkim's FieldName but does not allow ";" in name
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseSignedHeaders;

impl Error for ParseSignedHeaders {}

impl Display for ParseSignedHeaders {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse signed headers")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SignedHeaders {
    Pick(Vec<SignedFieldName>),  // must contain From
    PickWithDefault(Vec<SignedFieldName>),  // need not contain From
    All,
}

impl FromStr for SignedHeaders {
    type Err = ParseSignedHeaders;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // assumes s is already trimmed

        if let Some(rest) = s.strip_prefix("default") {
            if rest.is_empty() {
                return Ok(Self::PickWithDefault(vec![]));
            }

            let s = rest.trim_start();
            if let Some(rest) = s.strip_prefix(';') {
                let s = rest.trim_start();

                // now treat s as colon-separated field name values
                let result = split_at_colon(s)
                    .map(|x| {
                        x.and_then(|s| SignedFieldName::new(s).map_err(|_| ParseSignedHeaders))
                    })
                .collect::<Result<_, _>>()?;
                return Ok(Self::PickWithDefault(result));
            }
        } else if let Some(rest) = s.strip_prefix("all") {
            if rest.is_empty() {
                return Ok(Self::All);
            }
        } else {
            // parse colon-separated field name values
            let result: Vec<_> = split_at_colon(s)
                .map(|x| {
                    x.and_then(|s| SignedFieldName::new(s).map_err(|_| ParseSignedHeaders))
                })
                .collect::<Result<_, _>>()?;
            if !result.iter().any(|n| *n.as_ref() == "From") {
                return Err(ParseSignedHeaders);
            }
            return Ok(Self::Pick(result));
        }

        Err(ParseSignedHeaders)
    }
}

// colon cannot appear in field names, so is a good choice for the separator
pub fn split_at_colon(value: &str) -> impl Iterator<Item = Result<&str, ParseSignedHeaders>> {
    let value = value.trim();

    let mut values = value.split(':');

    // If the value is empty, `split` will yield one empty string slice. In that
    // case, drop this string so that the iterator becomes empty.
    if value.is_empty() {
        values.next();
    }

    values.map(|s| {
        let s = s.trim();
        if s.is_empty() {
            Err(ParseSignedHeaders)
        } else {
            Ok(s)
        }
    })
}

// TODO
#[derive(Clone, Debug, PartialEq)]
pub enum OversignedHeaders {
    Pick(Vec<SignedFieldName>),
}

impl FromStr for OversignedHeaders {
    type Err = ParseSignedHeaders;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // assumes s is already trimmed

        // parse colon-separated field name values
        let result: Vec<_> = split_at_colon(s)
            .map(|x| x.and_then(|s| SignedFieldName::new(s).map_err(|_| ParseSignedHeaders)))
            .collect::<Result<_, _>>()?;
        Ok(Self::Pick(result))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseExpirationError;

impl Error for ParseExpirationError {}

impl Display for ParseExpirationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse expiration")
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Expiration {
    Never,
    After(Duration),  // non-zero
}

impl FromStr for Expiration {
    type Err = ParseExpirationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // assumes s is already trimmed

        if s == "never" {
            return Ok(Self::Never);
        }

        let duration = parse_expiration_duration(s).map_err(|_| ParseExpirationError)?;

        Ok(Self::After(duration))
    }
}

fn parse_expiration_duration(s: &str) -> Result<Duration, ParseIntError> {
    let seconds = if let Some(s) = s.strip_suffix("d") {
        let days = NonZeroU32::from_str(s.trim_end())?;
        let scale = NonZeroU32::new(24 * 60 * 60).unwrap();
        days.saturating_mul(scale)
    } else if let Some(s) = s.strip_suffix("h") {
        let hours = NonZeroU32::from_str(s.trim_end())?;
        let scale = NonZeroU32::new(60 * 60).unwrap();
        hours.saturating_mul(scale)
    } else if let Some(s) = s.strip_suffix("m") {
        let minutes = NonZeroU32::from_str(s.trim_end())?;
        let scale = NonZeroU32::new(60).unwrap();
        minutes.saturating_mul(scale)
    } else {
        let s = s.strip_suffix("s").unwrap_or(s);
        NonZeroU32::from_str(s.trim_end())?
    };
    Ok(Duration::from_secs(seconds.get().into()))
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
    pub fn combine_with(&self, overrides: &SigningConfigOverrides) -> Self {
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
        config
    }
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            default_signed_headers: signer::default_signed_headers().into_iter()
                .map(|f| SignedFieldName(f))
                .collect(),
            default_unsigned_headers: signer::default_unsigned_headers().into_iter()
                .map(|f| SignedFieldName(f))
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
pub struct SigningConfigOverrides {
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

impl SigningConfigOverrides {
    pub fn into_signing_config(self) -> SigningConfig {
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
        config
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationConfig {
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationConfigOverrides {
}

// ...

#[derive(Clone, Debug)]
pub struct OverrideEntry {
    pub expr: Regex,
    pub config: SigningConfigOverrides,
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
    pub signing_config: Option<SigningConfigOverrides>,
}
