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

//! The DKIM Milter application library.
//!
//! This library was published to facilitate integration testing of the [DKIM
//! Milter application][DKIM Milter]. No backwards compatibility guarantees are
//! made for the public API in this library. Please look into the application
//! instead.
//!
//! [DKIM Milter]: https://crates.io/crates/dkim-milter

mod auth_results;
mod callbacks;
mod config;
mod datastore;
mod format;
mod resolver;
mod session;
mod sign;
mod util;
mod verify;

pub use crate::{
    config::{
        model::{
            LogDestination, LogLevel, ParseLogDestinationError, ParseLogLevelError,
            ParseSocketError, ParseSyslogFacilityError, Socket, SyslogFacility,
        },
        CliOptions,
    },
    resolver::LookupFuture,
};

use crate::{
    config::{LogConfig, SessionConfig},
    resolver::MockLookupTxt,
};
use indymilter::IntoListener;
use log::{error, info, LevelFilter, Log, Metadata, Record, SetLoggerError};
use std::{
    error::Error,
    future::Future,
    io::{self, stderr, ErrorKind, Write},
    sync::{Arc, RwLock},
};
use tokio::sync::mpsc;

/// The DKIM Milter application name.
pub const MILTER_NAME: &str = "DKIM Milter";

/// The DKIM Milter version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Preliminary, partially read configuration, with logger not yet installed.
pub struct StubConfig {
    opts: CliOptions,
    log_config: LogConfig,
    config_file_content: String,
}

impl StubConfig {
    pub async fn read(opts: CliOptions) -> Result<Self, Box<dyn Error + 'static>> {
        let (log_config, config_file_content) = match LogConfig::read(&opts).await {
            Ok(config) => config,
            Err(e) => return Err(Box::new(e)),
        };

        Ok(Self {
            opts,
            log_config,
            config_file_content,
        })
    }

    pub fn install_static_logger(&self) -> Result<(), Box<dyn Error + 'static>> {
        configure_logging(&self.log_config)?;
        Ok(())
    }

    pub async fn read_fully(self) -> Result<Config, Box<dyn Error + 'static>> {
        let StubConfig { opts, log_config, config_file_content } = self;
        Config::read_fully(opts, log_config, &config_file_content, None).await
    }

    pub async fn read_fully_with_lookup(
        self,
        lookup: impl Fn(&str) -> LookupFuture + Send + Sync + 'static,
    ) -> Result<Config, Box<dyn Error + 'static>> {
        let StubConfig { opts, log_config, config_file_content } = self;
        let lookup = Arc::new(lookup);
        Config::read_fully(opts, log_config, &config_file_content, Some(lookup)).await
    }
}

pub struct Config {
    cli_opts: CliOptions,
    config: config::Config,
    mock_resolver: Option<MockLookupTxt>,
}

// Note: `Config::read` is stateful, as it installs a global logger on first
// use; this logger is active for the rest of the program.
impl Config {
    pub async fn read(opts: CliOptions) -> Result<Self, Box<dyn Error + 'static>> {
        Self::read_internal(opts, None).await
    }

    pub async fn read_with_lookup(
        opts: CliOptions,
        lookup: impl Fn(&str) -> LookupFuture + Send + Sync + 'static,
    ) -> Result<Self, Box<dyn Error + 'static>> {
        let lookup = Arc::new(lookup);
        Self::read_internal(opts, Some(lookup)).await
    }

    async fn read_internal(
        opts: CliOptions,
        mock_resolver: Option<Arc<dyn Fn(&str) -> LookupFuture + Send + Sync>>,
    ) -> Result<Self, Box<dyn Error + 'static>> {
        let config = StubConfig::read(opts).await?;

        config.install_static_logger()?;

        // Logging now available; from here on, use logging via log macros.

        let StubConfig { opts, log_config, config_file_content } = config;

        Self::read_fully(opts, log_config, &config_file_content, mock_resolver).await
    }

    async fn read_fully(
        opts: CliOptions,
        log_config: LogConfig,
        config_file_content: &str,
        mock_resolver: Option<Arc<dyn Fn(&str) -> LookupFuture + Send + Sync>>,
    ) -> Result<Self, Box<dyn Error + 'static>> {
        let config = match config::Config::read_with_log_config(
            &opts,
            log_config,
            config_file_content,
        )
        .await
        {
            Ok(config) => config,
            Err(e) => {
                return Err(Box::new(e));
            }
        };

        let mock_resolver = mock_resolver.map(MockLookupTxt::new);

        Ok(Self {
            cli_opts: opts,
            config,
            mock_resolver,
        })
    }

    pub fn socket(&self) -> &Socket {
        &self.config.socket
    }
}

fn configure_logging(config: &LogConfig) -> Result<(), Box<dyn Error + 'static>> {
    let level = match config.log_level {
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Debug,
    };

    match config.log_destination {
        LogDestination::Syslog => {
            syslog::init_unix(config.syslog_facility.into(), level).map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("could not initialize syslog: {e}"),
                )
            })?;
        }
        LogDestination::Stderr => {
            StderrLog::init(level).map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("could not initialize stderr log: {e}"),
                )
            })?;
        }
    }

    Ok(())
}

pub async fn run(
    listener: impl IntoListener,
    config: Config,
    reload: mpsc::Receiver<()>,
    shutdown: impl Future,
) -> io::Result<()> {
    let Config { cli_opts, config, mock_resolver } = config;

    let session_config = match mock_resolver {
        Some(resolver) => SessionConfig::with_mock_resolver(config, resolver),
        None => SessionConfig::new(config),
    };
    let session_config = Arc::new(RwLock::new(Arc::new(session_config)));

    spawn_reload_task(session_config.clone(), cli_opts, reload);

    let callbacks = callbacks::make_callbacks(session_config);
    let config = Default::default();

    info!("{MILTER_NAME} {VERSION} starting");

    let result = indymilter::run(listener, callbacks, config, shutdown).await;

    match &result {
        Ok(()) => info!("{MILTER_NAME} {VERSION} shut down"),
        Err(e) => error!("{MILTER_NAME} {VERSION} terminated with error: {e}"),
    }

    result
}

fn spawn_reload_task(
    session_config: Arc<RwLock<Arc<SessionConfig>>>,
    opts: CliOptions,
    mut reload: mpsc::Receiver<()>,
) {
    tokio::spawn(async move {
        while let Some(()) = reload.recv().await {
            config::reload(&session_config, &opts).await;
        }
    });
}

/// A minimal log implementation that uses `writeln!` for logging.
struct StderrLog {
    level: LevelFilter,
}

impl StderrLog {
    fn init<L: Into<LevelFilter>>(level: L) -> Result<(), SetLoggerError> {
        let level = level.into();
        log::set_boxed_logger(Box::new(Self { level }))
            .map(|_| log::set_max_level(level))
    }
}

impl Log for StderrLog {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let _ = writeln!(stderr(), "{}", record.args());
        }
    }

    fn flush(&self) {}
}
