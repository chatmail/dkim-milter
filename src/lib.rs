mod auth_results;
mod callbacks;
mod config;
mod format;
mod resolver;
mod session;

pub use crate::config::{
    model::{LogDestination, ParseLogDestinationError, ParseSocketError, Socket},
    CliOptions, Config,
};

use indymilter::IntoListener;
use std::{future::Future, io, sync::Arc};
use tracing::{error, info};

/// The DKIM Milter application name.
pub const MILTER_NAME: &str = "DKIM Milter";

/// The DKIM Milter version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn run(
    listener: impl IntoListener,
    config: Config,
    shutdown: impl Future,
) -> io::Result<()> {
    let config = Arc::new(config);

    let callbacks = callbacks::make_callbacks(config);
    let config = Default::default();

    info!("{MILTER_NAME} {VERSION} starting");

    let result = indymilter::run(listener, callbacks, config, shutdown).await;

    match &result {
        Ok(()) => info!("{MILTER_NAME} {VERSION} shut down"),
        Err(e) => error!("{MILTER_NAME} {VERSION} terminated with error: {e}"),
    }

    result
}
