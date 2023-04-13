use regex::Regex;
use std::{
    error::Error,
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
    sync::Arc,
};
use viadkim::{
    crypto::SigningKey,
    signature::{Canonicalization, CanonicalizationAlgorithm, DomainName, Selector},
};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseLogDestinationError;

impl Error for ParseLogDestinationError {}

impl Display for ParseLogDestinationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse log destination")
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LogDestination {
    Journald,
    Stderr,
}

impl Default for LogDestination {
    fn default() -> Self {
        Self::Journald
    }
}

impl FromStr for LogDestination {
    type Err = ParseLogDestinationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "journald" => Ok(Self::Journald),
            "stderr" => Ok(Self::Stderr),
            _ => Err(ParseLogDestinationError),
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
}

#[derive(Clone, Debug, PartialEq)]
pub struct SigningConfig {
    pub canonicalization: Canonicalization,
    pub copy_headers: bool,
    pub limit_body_length: bool,
}

impl SigningConfig {
    pub fn combine_with(&self, overrides: &SigningConfigOverrides) -> Self {
        let mut config = self.clone();
        if let Some(canonicalization) = overrides.canonicalization {
            config.canonicalization = canonicalization;
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
            canonicalization: Canonicalization {
                header: CanonicalizationAlgorithm::Relaxed,
                body: CanonicalizationAlgorithm::Simple,
            },
            copy_headers: false,
            limit_body_length: false,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SigningConfigOverrides {
    pub canonicalization: Option<Canonicalization>,
    pub copy_headers: Option<bool>,
    pub limit_body_length: Option<bool>,
}

impl SigningConfigOverrides {
    pub fn into_signing_config(self) -> SigningConfig {
        let mut config = SigningConfig::default();
        if let Some(canonicalization) = self.canonicalization {
            config.canonicalization = canonicalization;
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
