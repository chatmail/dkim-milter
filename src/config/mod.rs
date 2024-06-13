// DKIM Milter – milter for DKIM signing and verification
// Copyright © 2022–2024 David Bürgin <dbuergin@gluet.ch>
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

pub mod format;
pub mod model;
pub mod params;
pub mod reload;

pub use reload::reload;

use crate::{
    config::{
        format::{ParseConfigError, ValidationError},
        model::{
            LogDestination, LogLevel, OpMode, SigningConfig, Socket, SyslogFacility,
            TrustedNetworks, VerificationConfig,
        },
    },
    datastore::{ConnectionOverridesDb, RecipientOverridesDb, SigningKeysDb, SigningSendersDb},
    resolver::{DomainResolver, MockLookupTxt, Resolver},
};
use log::error;
use std::{
    error::Error,
    fmt::{self, Display, Formatter, Write},
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

const DEFAULT_CONFIG_FILE: &str = match option_env!("DKIM_MILTER_CONFIG_FILE") {
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
    pub syslog_facility: Option<SyslogFacility>,
}

pub struct SessionConfig {
    pub config: Config,
    pub resolver: Resolver,
}

impl SessionConfig {
    pub fn new(config: Config) -> Self {
        let resolver = Resolver::Live(DomainResolver::new(config.lookup_timeout));
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

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to read configuration from {}", self.file.display())
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

#[derive(Debug)]
pub enum ConfigErrorKind {
    Io(io::Error),
    Parse(ParseConfigError),
    Validation(ValidationError),
}

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

pub fn log_errors(id: Option<&str>, mut error: &(dyn Error + 'static)) {
    let mut msg = format!("{error}");

    while let Some(next) = error.source() {
        error = next;
        write!(msg, ": {error}").unwrap();
    }

    match id {
        Some(id) => error!("{id}: {msg}"),
        None => error!("{msg}"),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LogConfig {
    pub log_destination: LogDestination,
    pub log_level: LogLevel,
    pub syslog_facility: SyslogFacility,
}

// preliminary reading of LogConfig only, also returns config file content
impl LogConfig {
    pub async fn read(opts: &CliOptions) -> Result<(Self, String), ConfigError> {
        format::read_log_config(opts).await
    }
}

#[derive(Debug)]
pub struct Config {
    pub authserv_id: Option<String>,
    pub connection_overrides: Option<Box<dyn ConnectionOverridesDb>>,
    pub delete_incoming_authentication_results: bool,
    pub dry_run: bool,
    pub log_config: LogConfig,
    pub lookup_timeout: Duration,
    pub mode: OpMode,
    pub recipient_overrides: Option<Box<dyn RecipientOverridesDb>>,
    pub require_envelope_sender_match: bool,
    pub signing_config: SigningConfig,
    pub signing_keys: Option<Box<dyn SigningKeysDb>>,
    pub signing_senders: Option<Box<dyn SigningSendersDb>>,
    pub socket: Socket,
    pub trust_authenticated_senders: bool,
    pub trusted_networks: TrustedNetworks,
    pub verification_config: VerificationConfig,
}

impl Config {
    pub async fn read_with_log_config(
        opts: &CliOptions,
        log_config: LogConfig,
        main_config_file_content: &str,
    ) -> Result<Self, ConfigError> {
        format::read_config_with_log_config(opts, log_config, main_config_file_content).await
    }

    pub async fn read(opts: &CliOptions) -> Result<Self, ConfigError> {
        format::read_config(opts).await
    }
}
