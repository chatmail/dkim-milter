mod auth_results;
mod callbacks;
mod config;
mod format;
mod resolver;
mod session;
mod verify;
mod sign;

pub use crate::{
    config::{
        model::{
            LogDestination, LogLevel, ParseLogDestinationError, ParseLogLevelError,
            ParseSocketError, Socket,
        },
        CliOptions, LogConfig, SessionConfig,
    },
    resolver::LookupFuture,
};

use crate::resolver::MockLookupTxt;
use indymilter::IntoListener;
use std::{
    error::Error,
    future::Future,
    io::{self, stderr, ErrorKind, Write},
    sync::{Arc, RwLock},
};
use tokio::sync::mpsc;
use log::{error, info, LevelFilter, Log, Metadata, Record, SetLoggerError};
/*
use tracing::{error, info, Level};
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};
*/

/// The DKIM Milter application name.
pub const MILTER_NAME: &str = "DKIM Milter";

/// The DKIM Milter version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Config {
    cli_opts: CliOptions,
    config: config::Config,
    mock_resolver: Option<MockLookupTxt>,
}

// important: Config::read is stateful, as it installs a global tracing subscriber on first use;
// this subscriber is active for the rest of the program!
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
        // read subset of config first, to configure logging only
        let log_config = match LogConfig::read(&opts).await {
            Ok(config) => config,
            Err(e) => return Err(Box::new(e)),
        };

        configure_logging(&log_config)?;

        // logging now available; from here on, use logging via tracing macros

        // then actually read whole configuration
        let config = match config::Config::read(&opts).await {
            Ok(config) => config,
            Err(e) => {
                // dbg!(&e);
                return Err(Box::new(e));
            }
        };
        // dbg!(&config);

        let mock_resolver = mock_resolver.map(|r| MockLookupTxt { mock_resolver: r });

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
    // TODO `tracing` is simply not ready yet
    /*
    let registry = tracing_subscriber::registry();

    let level = match config.log_level {
        LogLevel::Error => Level::ERROR,
        LogLevel::Warn => Level::WARN,
        LogLevel::Info => Level::INFO,
        LogLevel::Debug => Level::DEBUG,
    };

    let filter = Targets::new()
        .with_default(level)
        // TODO actually, should enable level only for mod dkim_milter; however, then tests don't log
        // TODO `module_path!` only works if this code is in src/lib.rs
        // .with_target(module_path!(), level)
        // TODO during initial development, may enable viadkim trace logging
        // .with_target("viadkim", Level::TRACE)
        ;

    match config.log_destination {
        LogDestination::Journald => {
            let journald = tracing_journald::layer()?;
            // TODO this needs https://github.com/tokio-rs/tracing/pull/2347
            registry.with(journald).with(filter).try_init()?;
        }
        LogDestination::Stderr => {
            let stderr = tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_level(false)
                .without_time()
                .with_writer(stderr);
            registry.with(stderr).with(filter).try_init()?;
        }
    }
    */

    let level = match config.log_level {
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Debug,
    };

    match config.log_destination {
        LogDestination::Syslog => {
            syslog::init_unix(config.syslog_facility.into(), level)
                .map_err(|e| {
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
