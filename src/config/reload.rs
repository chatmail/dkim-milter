use crate::{
    config::{get_default_config_file, CliOptions, Config, SessionConfig},
    resolver::{DomainResolver, Resolver},
};
use log::{error, info};
use std::{
    mem,
    sync::{Arc, RwLock},
};

// TODO
pub async fn reload(current_session_config: &RwLock<Arc<SessionConfig>>, opts: &CliOptions) {
    let config_file = get_default_config_file(opts);

    let config = match Config::read(opts).await {
        Ok(config) => config,
        Err(e) => {
            error!("failed to reload configuration: {e}");
            return;
        }
    };

    // TODO record params that cannot be reloaded, report later

    let _old_cfg = {
        let mut locked_config = current_session_config
            .write()
            .expect("could not get configuration write lock");

        let resolver = match &locked_config.resolver {
            Resolver::Live(_) => Resolver::Live(DomainResolver::new()),
            Resolver::Mock(m) => Resolver::Mock(m.clone()),
        };
        let session_config = SessionConfig { config, resolver };

        mem::replace(&mut *locked_config, Arc::new(session_config))
    };

    info!("configuration reloaded from {}", config_file.display());
}
