// TODO
// #![allow(unused_imports, unused_variables)]
// #![allow(dead_code, unused_imports, unused_variables)]

mod auth_results;
mod callbacks;
mod config;
mod crypto;
mod format;
mod resolver;
mod session;

use crate::config::Config;
use indymilter::IntoListener;
use std::{future::Future, io, path::PathBuf, sync::Arc};
use tracing::info;

/// The DKIM Milter application name.
pub const MILTER_NAME: &str = "DKIM Milter";

/// The DKIM Milter version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn run(listener: impl IntoListener, shutdown: impl Future) -> io::Result<()> {
    let rsa_key_path = PathBuf::from("testkey_rsa.pem");
    let ed25519_key_path = PathBuf::from("testkey_ed25519.pem");

    let (keys_path_to_id, keys_id_to_key) =
        crypto::make_key_store(&rsa_key_path, &ed25519_key_path).await?;

    // TODO
    let default_config = Config {
        keys_path_to_id,
        keys_id_to_key,
        rsa_key_path,
        ed25519_key_path,
        authserv_id: "example.gluet.ch".into(),
        domain_to_sign: "gluet.ch".into(),
    };
    let default_config = Arc::new(default_config);

    let callbacks = callbacks::make_callbacks(default_config);
    let config = Default::default();

    info!("{} {} starting", MILTER_NAME, VERSION);

    indymilter::run(listener, callbacks, config, shutdown).await
}
