pub mod model;
pub mod parse;
pub mod read;

use crate::{
    config::{
        model::{
            LogConfig, LogDestination, LogLevel, OperationMode, SigningConfig, SigningOverrides,
            SigningSenders, Socket, VerificationConfig,
        },
        parse::{ParseConfigError, ValidationError},
    },
    resolver::{DomainResolver, Resolver},
    MockLookupTxt,
};
use log::{error, info};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    io, mem,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
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

pub struct Config {
    pub socket: Socket,
    pub mode: OperationMode,
    pub authserv_id: Option<String>,
    pub signing_senders: SigningSenders,
    // pub signing_keys: HashMap<String, Arc<SigningKey>>,
    // TODO
    pub recipient_overrides: Option<SigningOverrides>,  // <Regex, SigningConfig>
    // pub verification_overrides: X,  // <Regex, VerificationConfig>
    pub log_config: LogConfig,

    pub signing_config: SigningConfig,
    pub verification_config: VerificationConfig,
    pub fail_if_expired: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("socket", &self.socket)
            .field("mode", &self.mode)
            .field("authserv_id", &self.authserv_id)
            // TODO
            .field("signing_senders", &"<omitted>")//&self.signing_senders)
            // .field("signing_keys", &"<omitted>")
            .field("recipient_overrides", &self.recipient_overrides)
            .field("log_config", &self.log_config)
            .field("signing_config", &self.signing_config)
            .field("verification_config", &self.verification_config)
            .field("fail_if_expired", &self.fail_if_expired)
            .finish()
    }
}

impl Config {
    pub async fn read(opts: &CliOptions) -> Result<Self, ConfigError> {
        read::read_config(opts).await
    }
}

// TODO
pub async fn reload(current_runtime: &RwLock<Arc<RuntimeConfig>>, opts: &CliOptions) {
    let config_file = get_default_config_file(opts);

    let config = match Config::read(opts).await {
        Ok(config) => config,
        Err(e) => {
            error!("failed to reload configuration: {e}");
            return;
        }
    };

    // TODO record params that cannot be reloaded, report later

    let _old_runtime = {
        let mut locked_runtime = current_runtime
            .write()
            .expect("could not get configuration write lock");

        let resolver = match &locked_runtime.resolver {
            Resolver::Live(_) => Resolver::Live(DomainResolver::new()),
            Resolver::Mock(m) => Resolver::Mock(m.clone()),
        };
        let runtime = RuntimeConfig { config, resolver };

        mem::replace(&mut *locked_runtime, Arc::new(runtime))
    };

    info!("configuration reloaded from {}", config_file.display());
}
