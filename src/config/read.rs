use crate::config::{
    self,
    model::{LogConfig, SenderEntry, SigningConfigOverrides, SigningOverrides, SigningSenders},
    parse::{self, ParseConfigError, ParseParamError, TableError, TableErrorKind, TempSenderEntry},
    CliOptions, Config, ConfigError, ConfigErrorKind,
};
use std::{
    collections::{HashMap, HashSet},
    io,
    sync::Arc,
};
use tokio::fs;
use log::warn;
use viadkim::crypto::SigningKey;

// preliminary, loose reading of LogConfig only
// TODO ugh, move
impl LogConfig {
    pub async fn read(opts: &CliOptions) -> Result<Self, ConfigError> {
        read_log_config(opts).await
    }
}

pub async fn read_log_config(opts: &CliOptions) -> Result<LogConfig, ConfigError> {
    let config_file = config::get_default_config_file(opts);

    async {
        let file_content = fs::read_to_string(config_file).await?;
        let config = parse::parse_log_config(opts, &file_content).await?;
        Ok(config)
    }
    .await
    .map_err(|e| ConfigError {
        file: config_file.into(),
        kind: e,
    })
}

pub async fn read_config(opts: &CliOptions) -> Result<Config, ConfigError> {
    let config_file = config::get_default_config_file(opts);

    read_config_internal(opts)
        .await
        .map_err(|e| ConfigError {
            file: config_file.into(),
            kind: e,
        })
}

async fn read_config_internal(opts: &CliOptions) -> Result<Config, ConfigErrorKind> {
    let config_file = config::get_default_config_file(opts);

    let file_content = fs::read_to_string(config_file).await?;

    let config = parse::parse_config(opts, &file_content).await?;

    Ok(config)
}

pub async fn read_signing_config(
    signing_keys_file: (usize, &str),
    signing_senders_file: (usize, &str),
) -> Result<SigningSenders, ParseConfigError> {
    // Note: idea here is to warn but continue with an incomplete config and
    // only actually log an error when the milter is unable to sign a message
    // (for example, such a config does not prevent *verification* from working properly)
    // TODO warnings about not being able to sign should only be printed if signing mode is enabled

    let signing_keys = read_signing_keys_table(signing_keys_file.1)
        .await
        .map_err(|e| ParseConfigError {
            line: signing_keys_file.0,
            kind: ParseParamError::ReadSigningKeys(e),
        })?;

    if signing_keys.is_empty() {
        warn!("no signing keys available, no signing will be done");
    }

    let mut signing_senders = read_signing_senders_table(signing_senders_file.1)
        .await
        .map_err(|e| ParseConfigError {
            line: signing_senders_file.0,
            kind: ParseParamError::ReadSigningSenders(e),
        })?;

    signing_senders.retain(|entry| {
        let ret = signing_keys.contains_key(&entry.key_name);
        if !ret {
            warn!("key name \"{}\" not found in signing keys, ignoring entry", entry.key_name);
        }
        ret
    });

    let mut key_names: HashSet<_> = signing_keys.keys().collect();

    for entry in &signing_senders {
        key_names.remove(&entry.key_name);
    }

    for name in key_names {
        warn!("unused signing key \"{}\" found in signing keys", name);
    }

    if signing_senders.is_empty() {
        warn!("no sender exprs available, no signing will be done");
    }

    let key_store: HashMap<_, _> = signing_keys.into_iter().map(|(k, v)| {
        (k, Arc::new(v))
    }).collect();

    let entries: Vec<_> = signing_senders.into_iter().map(|entry| {
        SenderEntry {
            sender_expr: entry.sender_expr,
            domain: entry.domain,
            selector: entry.selector,
            key_name: Arc::clone(&key_store.get(&entry.key_name).unwrap()),
            signing_config: entry.signing_config,
        }
    }).collect();

    let signing_senders = SigningSenders {
        entries,
    };

    Ok(signing_senders)
}

async fn read_signing_keys_table(
    file_name: &str,
) -> Result<HashMap<String, SigningKey>, TableError> {
    async {
        let file_content = fs::read_to_string(file_name).await?;

        let map = parse::parse_signing_keys_table(&file_content).await?;

        Ok(map)
    }
    .await
    .map_err(|e| TableError::new(file_name, e))
}

pub async fn read_signing_key(
    file_name: &str,
) -> io::Result<SigningKey> {
    let key_file_content = match fs::read_to_string(file_name).await {
        Ok(k) => k,
        Err(e) => {
            return Err(e);
            // warn!(
            //     "could not read signing key \"{}\" from file, ignoring key",
            //     k
            // );
            // continue;
        }
    };

    let key = SigningKey::from_pkcs8_pem(&key_file_content)?;

    Ok(key)
}

async fn read_signing_senders_table(file_name: &str) -> Result<Vec<TempSenderEntry>, TableError> {
    read_signing_senders_table_internal(file_name)
        .await
        .map_err(|e| TableError::new(file_name, e))
}

async fn read_signing_senders_table_internal(
    file_name: &str,
) -> Result<Vec<TempSenderEntry>, TableErrorKind> {
    let file_content = fs::read_to_string(file_name).await?;

    let map = parse::parse_signing_senders_table(&file_content).await?;

    Ok(map)
}

pub async fn read_recipient_overrides_table(
    file_name: &str,
) -> Result<SigningOverrides, TableError> {
    async {
        let file_content = fs::read_to_string(file_name).await?;

        let overrides = parse::parse_recipient_overrides_table(&file_content).await?;

        Ok(SigningOverrides { entries: overrides })
    }
    .await
    .map_err(|e| TableError::new(file_name, e))
}

pub async fn read_signing_config_overrides(
    file_name: &str,
) -> Result<SigningConfigOverrides, ConfigError> {
    async {
        let file_content = fs::read_to_string(file_name).await?;

        let overrides = parse::parse_signing_config_overrides(&file_content).await?;

        Ok(overrides)
    }
    .await
    .map_err(|e| ConfigError {
        file: file_name.into(),
        kind: e,
    })
}
