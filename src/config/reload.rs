use crate::{
    config::{get_default_config_file, CliOptions, Config, SessionConfig},
    resolver::{DomainResolver, Resolver},
};
use log::{error, info, warn};
use std::{
    mem,
    sync::{Arc, RwLock},
};

pub async fn reload(current_session_config: &RwLock<Arc<SessionConfig>>, opts: &CliOptions) {
    let config_file = get_default_config_file(opts);

    info!("reloading configuration");

    let mut config = match Config::read(opts).await {
        Ok(config) => config,
        Err(e) => {
            // TODO revisit single-line format of this error
            error!("failed to reload configuration: {e}");
            return;
        }
    };

    let mut rejected_socket = None;
    let mut rejected_log_config = None;

    let old_config = {
        let mut locked_config = current_session_config
            .write()
            .expect("could not get configuration write lock");

        // for params that cannot be reloaded, restore them to original value in
        // newly loaded config
        if config.socket != locked_config.config.socket {
            let old_socket = locked_config.config.socket.clone();
            rejected_socket = Some(mem::replace(&mut config.socket, old_socket));
        }
        if config.log_config != locked_config.config.log_config {
            let old_log_config = locked_config.config.log_config.clone();
            rejected_log_config = Some(mem::replace(&mut config.log_config, old_log_config));
        }

        let resolver = match &locked_config.resolver {
            Resolver::Live(_) => Resolver::Live(DomainResolver::new(config.lookup_timeout)),
            Resolver::Mock(m) => Resolver::Mock(m.clone()),
        };

        let session_config = SessionConfig { config, resolver };

        mem::replace(&mut *locked_config, Arc::new(session_config))
    };

    info!("configuration reloaded from {}", config_file.display());

    if let Some(_rejected_socket) = rejected_socket {
        warn_param_not_reloaded("socket");
    }

    if let Some(rejected_log_config) = rejected_log_config {
        let old_log_config = &old_config.config.log_config;

        if rejected_log_config.log_destination != old_log_config.log_destination {
            warn_param_not_reloaded("log_destination");
        }
        if rejected_log_config.log_level != old_log_config.log_level {
            warn_param_not_reloaded("log_level");
        }
        if rejected_log_config.syslog_facility != old_log_config.syslog_facility {
            warn_param_not_reloaded("syslog_facility");
        }
    }
}

fn warn_param_not_reloaded(name: &str) {
    warn!("new value for parameter \"{name}\" not loaded, restart needed");
}
