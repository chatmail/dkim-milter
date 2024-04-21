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

use crate::{
    config::{self, CliOptions, Config, SessionConfig},
    resolver::{DomainResolver, Resolver},
};
use log::{error, info, warn};
use std::{
    mem,
    sync::{Arc, RwLock},
};

pub async fn reload(current_session_config: &RwLock<Arc<SessionConfig>>, opts: &CliOptions) {
    let config_file = config::get_default_config_file(opts);

    info!("reloading configuration");

    let mut config = match Config::read(opts).await {
        Ok(config) => config,
        Err(e) => {
            config::log_errors(None, &e);
            error!("failed to reload configuration");
            return;
        }
    };

    let mut rejected_socket = None;
    let mut rejected_log_config = None;

    let old_config = {
        let mut locked_config = current_session_config.write()
            .expect("could not get configuration write lock");

        // For params that cannot be reloaded, restore them to original value in
        // newly loaded config: repeated reloading, repeated warning.
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
