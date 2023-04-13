pub mod model;
pub mod parse;
pub mod read;

use crate::config::{
    model::{
        LogDestination, OperationMode, SigningConfig, SigningOverrides, SigningSenders, Socket,
        VerificationConfig,
    },
    parse::{ParseConfigError, ValidationError},
};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    io,
    path::PathBuf,
};

const DEFAULT_CONFIG_FILE: &str = match option_env!("DKIM_MILTER_CONFIG_FILE") {
    Some(s) => s,
    None => "/etc/dkim-milter/dkim-milter.conf",
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliOptions {
    // TODO config_file should be Option as well, default value belongs elsewhere
    pub config_file: PathBuf,
    pub log_destination: Option<LogDestination>,
    pub socket: Option<Socket>,
}

impl Default for CliOptions {
    fn default() -> Self {
        Self {
            config_file: DEFAULT_CONFIG_FILE.into(),
            log_destination: None,
            socket: None,
        }
    }
}

struct ConfigErrorDisplay<'a> {
    inner: &'a ConfigError,
    multiline: bool,
}

impl Display for ConfigErrorDisplay<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut error: &(dyn Error + 'static) = self.inner;
        write!(f, "{error}")?;
        while let Some(next) = error.source() {
            error = next;
            if self.multiline {
                writeln!(f)?;
                write!(f, "  {error}")?;
            } else {
                write!(f, ": {error}")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ConfigError {
    pub file: PathBuf,
    pub kind: ConfigErrorKind,
}

impl ConfigError {
    pub fn display(&self) -> impl Display + '_ {
        ConfigErrorDisplay {
            inner: self,
            multiline: false,
        }
    }

    pub fn display_multiline(&self) -> impl Display + '_ {
        ConfigErrorDisplay {
            inner: self,
            multiline: true,
        }
    }
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
