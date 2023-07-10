// TODO `format` module name: file format? files? settings?
pub mod format;
pub mod reload;
pub mod model;
pub mod params;
pub mod tables;

pub use reload::reload;

use crate::{
    config::{
        format::{ParseConfigError, ValidationError},
        model::{
            LogDestination, LogLevel, OperationMode, SigningConfig, SigningOverrides,
            SigningSenders, Socket, TrustedNetworks,
        },
    },
    resolver::{DomainResolver, Resolver},
    MockLookupTxt,
};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

pub const DEFAULT_CONFIG_FILE: &str = match option_env!("DKIM_MILTER_CONFIG_FILE") {
    Some(s) => s,
    None => "/etc/dkim-milter/dkim-milter.conf",
};

pub fn get_default_config_file(opts: &CliOptions) -> &Path {
    opts.config_file.as_deref().unwrap_or_else(|| Path::new(DEFAULT_CONFIG_FILE))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CliOptions {
    pub config_file: Option<PathBuf>,
    pub dry_run: bool,
    pub log_destination: Option<LogDestination>,
    pub log_level: Option<LogLevel>,
    pub socket: Option<Socket>,
}

pub struct RuntimeConfig {
    pub config: Config,
    pub resolver: Resolver,
}

impl RuntimeConfig {
    pub fn new(config: Config) -> Self {
        let resolver = Resolver::Live(DomainResolver::new());
        Self { config, resolver }
    }

    pub fn with_mock_resolver(config: Config, resolver: MockLookupTxt) -> Self {
        let resolver = Resolver::Mock(Arc::new(resolver));
        Self { config, resolver }
    }
}

#[derive(Debug)]
pub struct ConfigError {
    pub file: PathBuf,
    pub kind: ConfigErrorKind,
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            ConfigErrorKind::Io(e) => Some(e),
            ConfigErrorKind::Parse(e) => Some(e),
            ConfigErrorKind::Validation(e) => Some(e),
        }
    }
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to read configuration from {}", self.file.display())
    }
}

#[derive(Debug)]
pub enum ConfigErrorKind {
    Io(io::Error),
    Parse(ParseConfigError),
    Validation(ValidationError),
}

// TODO delete?
impl Display for ConfigErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => write!(f, "I/O error"),
            Self::Parse(_) => write!(f, "error parsing configuration"),
            Self::Validation(_) => write!(f, "validation error"),
        }
    }
}

impl From<io::Error> for ConfigErrorKind {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ParseConfigError> for ConfigErrorKind {
    fn from(error: ParseConfigError) -> Self {
        Self::Parse(error)
    }
}

impl From<ValidationError> for ConfigErrorKind {
    fn from(error: ValidationError) -> Self {
        Self::Validation(error)
    }
}

#[derive(Clone, Debug)]
pub struct LogConfig {
    pub log_destination: LogDestination,
    pub log_level: LogLevel,
}

// preliminary, loose reading of LogConfig only
impl LogConfig {
    pub async fn read(opts: &CliOptions) -> Result<Self, ConfigError> {
        format::read_log_config(opts).await
    }
}

pub struct Config {
    pub authserv_id: Option<String>,
    pub allow_expired: bool,
    pub min_key_bits: usize,
    pub allow_sha1: bool,
    pub mode: OperationMode,
    pub recipient_overrides: Option<SigningOverrides>,
    pub signing_senders: SigningSenders,
    pub socket: Socket,
    pub trust_authenticated_senders: bool,
    pub trusted_networks: TrustedNetworks,
    pub dry_run: bool,

    pub log_config: LogConfig,
    pub signing_config: SigningConfig,
}

impl Config {
    pub async fn read(opts: &CliOptions) -> Result<Self, ConfigError> {
        format::read_config(opts).await
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // TODO
        f.debug_struct("Config")
            .field("authserv_id", &self.authserv_id)
            .field("allow_expired", &self.allow_expired)
            .field("min_key_bits", &self.min_key_bits)
            .field("allow_sha1", &self.allow_sha1)
            .field("mode", &self.mode)
            .field("recipient_overrides", &self.recipient_overrides)
            .field("signing_senders", &"<omitted>")
            .field("socket", &self.socket)
            .field("trust_authenticated_senders", &self.trust_authenticated_senders)
            .field("trusted_networks", &self.trusted_networks)
            .field("log_config", &self.log_config)
            .field("signing_config", &self.signing_config)
            .field("dry_run", &self.dry_run)
            .finish()
    }
}
