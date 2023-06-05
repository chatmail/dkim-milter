use crate::{
    config::{get_default_config_file, CliOptions, Config, RuntimeConfig},
    resolver::{DomainResolver, Resolver},
};
use log::{error, info};
use std::{
    mem,
    sync::{Arc, RwLock},
};

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
