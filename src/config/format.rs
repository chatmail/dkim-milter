//! Configuration file format.

use crate::config::{
    self,
    model::{
        ConfigOverrides, LogDestination, LogLevel, OperationMode, PartialSigningConfig,
        PartialVerificationConfig, SenderEntry, SignedFieldName, SigningSenders, Socket,
        SyslogFacility, TrustedNetworks,
    },
    params,
    tables::{self, TableError},
    CliOptions, Config, ConfigError, ConfigErrorKind, LogConfig,
};
use log::warn;
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::{self, Display, Formatter},
    str::FromStr,
    sync::Arc,
};
use tokio::fs;
use viadkim::signature::Canonicalization;

#[derive(Debug)]
pub enum ValidationError {
    MissingSocketParam,
    UnusableSigningConfig,
    IncompatibleSigningConfigOverrides,
}

impl Error for ValidationError {}

impl Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSocketParam => write!(f, "missing mandatory socket parameter"),
            Self::UnusableSigningConfig => write!(f, "unusable signing senders and/or keys configuration"),
            Self::IncompatibleSigningConfigOverrides => write!(f, "applying overrides resulted in invalid signing configuration"),
        }
    }
}

#[derive(Debug)]
pub struct ParseConfigError {
    pub line: usize,
    pub kind: ParseParamError,
}

impl ParseConfigError {
    pub fn new(line: usize, kind: ParseParamError) -> Self {
        Self { line, kind }
    }
}

impl Error for ParseConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use ParseParamError::*;

        match &self.kind {
            InvalidLine
            | UnknownKey(_)
            | DuplicateKey(_)
            | InvalidValue
            | InvalidLogDestination(_)
            | InvalidLogLevel(_)
            | InvalidSyslogFacility(_)
            | InvalidSocket(_)
            | InvalidBoolean(_)
            | InvalidU32(_)
            | InvalidNetworkAddress(_)
            | InvalidTrustedNetworks(_)
            | InvalidFieldName(_)
            | DuplicateFieldName(_)
            | SignedHeadersMissingFrom(_)
            | FromInUnsignedHeaders(_)
            | InvalidHashAlgorithm(_)
            | InvalidCanonicalization(_)
            | InvalidDuration(_)
            | InvalidExpiration(_)
            | InvalidRejectFailure(_)
            | InvalidMode(_) => None,
            ReadSigningKeys(e)
            | ReadSigningSenders(e)
            | ReadConnectionOverrides(e)
            | ReadRecipientOverrides(e) => Some(e),
        }
    }
}

impl Display for ParseConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use ParseParamError::*;

        write!(f, "parse error at line {}", self.line)?;

        match &self.kind {
            InvalidLine
            | UnknownKey(_)
            | DuplicateKey(_)
            | InvalidValue
            | InvalidLogDestination(_)
            | InvalidLogLevel(_)
            | InvalidSyslogFacility(_)
            | InvalidSocket(_)
            | InvalidBoolean(_)
            | InvalidU32(_)
            | InvalidNetworkAddress(_)
            | InvalidTrustedNetworks(_)
            | InvalidFieldName(_)
            | DuplicateFieldName(_)
            | SignedHeadersMissingFrom(_)
            | FromInUnsignedHeaders(_)
            | InvalidHashAlgorithm(_)
            | InvalidCanonicalization(_)
            | InvalidDuration(_)
            | InvalidExpiration(_)
            | InvalidRejectFailure(_)
            | InvalidMode(_) => write!(f, ": {}", self.kind),
            ReadSigningKeys(_)
            | ReadSigningSenders(_)
            | ReadConnectionOverrides(_)
            | ReadRecipientOverrides(_) => Ok(()),
        }
    }
}

// TODO rename *Kind?
#[derive(Debug)]
pub enum ParseParamError {
    InvalidLine,
    UnknownKey(String),
    DuplicateKey(String),
    InvalidValue,

    InvalidLogDestination(String),
    InvalidLogLevel(String),
    InvalidSyslogFacility(String),

    InvalidSocket(String),
    InvalidBoolean(String),
    InvalidU32(String),
    InvalidNetworkAddress(String),
    InvalidTrustedNetworks(String),
    InvalidFieldName(String),
    DuplicateFieldName(SignedFieldName),
    SignedHeadersMissingFrom(String),
    FromInUnsignedHeaders(String),
    InvalidHashAlgorithm(String),
    InvalidCanonicalization(String),
    InvalidDuration(String),
    InvalidExpiration(String),
    InvalidMode(String),
    InvalidRejectFailure(String),

    ReadSigningKeys(TableError),
    ReadSigningSenders(TableError),
    ReadConnectionOverrides(TableError),
    ReadRecipientOverrides(TableError),
}

impl Error for ParseParamError {}

impl Display for ParseParamError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // TODO move?
        match self {
            Self::InvalidLine => write!(f, "invalid line syntax"),
            Self::UnknownKey(key) => write!(f, "unknown parameter \"{key}\""),
            Self::DuplicateKey(key) => write!(f, "duplicate parameter \"{key}\""),
            Self::InvalidValue => write!(f, "invalid parameter value syntax"),

            Self::InvalidLogDestination(s) => write!(f, "invalid log destination \"{s}\""),
            Self::InvalidLogLevel(s) => write!(f, "invalid log level \"{s}\""),
            Self::InvalidSyslogFacility(s) => write!(f, "invalid syslog facility \"{s}\""),

            Self::InvalidSocket(s) => write!(f, "invalid socket \"{s}\""),
            Self::InvalidBoolean(s) => write!(f, "invalid Boolean value \"{s}\""),
            Self::InvalidU32(s) => write!(f, "invalid integer value \"{s}\""),
            Self::InvalidNetworkAddress(s) => write!(f, "invalid network address \"{s}\""),
            Self::InvalidTrustedNetworks(s) => write!(f, "invalid trusted networks \"{s}\""),
            Self::InvalidFieldName(s) => write!(f, "invalid header field name \"{s}\""),
            Self::DuplicateFieldName(s) => write!(f, "duplicate header field name \"{}\"", s.as_ref()),
            Self::SignedHeadersMissingFrom(_s) => write!(f, "signed headers are missing required header From"),
            Self::FromInUnsignedHeaders(_s) => write!(f, "unsigned headers contain required header From"),
            Self::InvalidHashAlgorithm(s) => write!(f, "invalid hash algorithm \"{s}\""),
            Self::InvalidCanonicalization(s) => write!(f, "invalid canonicalization \"{s}\""),
            Self::InvalidDuration(s) => write!(f, "invalid duration \"{s}\""),
            Self::InvalidExpiration(s) => write!(f, "invalid expiration duration \"{s}\""),
            Self::InvalidMode(s) => write!(f, "invalid operation mode \"{s}\""),
            Self::InvalidRejectFailure(s) => write!(f, "invalid rejection specification \"{s}\""),

            Self::ReadSigningKeys(_) => write!(f, "failed to read signing keys"),
            Self::ReadSigningSenders(_) => write!(f, "failed to read signing senders"),
            Self::ReadConnectionOverrides(_) => write!(f, "failed to read connection overrides"),
            Self::ReadRecipientOverrides(_) => write!(f, "failed to read recipient overrides"),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PartialLogConfig {
    pub log_destination: Option<LogDestination>,
    pub log_level: Option<LogLevel>,
    pub syslog_facility: Option<SyslogFacility>,
}

#[derive(Clone, Debug, Default)]
pub struct RawConfig {
    pub authserv_id: Option<String>,
    pub connection_overrides_file: Option<(usize, String)>,
    pub delete_incoming_authentication_results: Option<bool>,
    pub dry_run: Option<bool>,
    pub log_config: PartialLogConfig,
    pub mode: Option<OperationMode>,
    pub recipient_overrides_file: Option<(usize, String)>,
    pub signing_config: PartialSigningConfig,
    pub signing_keys_file: Option<(usize, String)>,
    pub signing_senders_file: Option<(usize, String)>,
    pub socket: Option<Socket>,
    pub trust_authenticated_senders: Option<bool>,
    pub trusted_networks: Option<TrustedNetworks>,
    pub verification_config: PartialVerificationConfig,
}

pub async fn read_log_config(opts: &CliOptions) -> Result<LogConfig, ConfigError> {
    let config_file = config::get_default_config_file(opts);

    async {
        let file_content = fs::read_to_string(config_file).await?;
        let config = parse_log_config(opts, &file_content).await?;
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

    async {
        let file_content = fs::read_to_string(config_file).await?;
        let config = parse_config(opts, &file_content).await?;
        Ok(config)
    }
    .await
    .map_err(|e| ConfigError {
        file: config_file.into(),
        kind: e,
    })
}

async fn read_signing_config(
    signing_keys_file: &(usize, String),
    signing_senders_file: &(usize, String),
) -> Result<SigningSenders, ParseConfigError> {
    // Note: idea here is to warn but continue with an incomplete config and
    // only actually log an error when the milter is unable to sign a message
    // (for example, such a config does not prevent *verification* from working properly)
    // TODO warnings about not being able to sign should only be printed if signing mode is enabled

    let signing_keys = tables::read_signing_keys_table(&signing_keys_file.1)
        .await
        .map_err(|e| ParseConfigError {
            line: signing_keys_file.0,
            kind: ParseParamError::ReadSigningKeys(e),
        })?;

    if signing_keys.is_empty() {
        warn!("no signing keys available, no signing will be done");
    }

    let mut signing_senders = tables::read_signing_senders_table(&signing_senders_file.1)
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
            key_name: Arc::clone(key_store.get(&entry.key_name).unwrap()),
            signing_config: entry.signing_config,
        }
    }).collect();

    let signing_senders = SigningSenders {
        entries,
    };

    Ok(signing_senders)
}

pub async fn read_config_overrides(
    file_name: &str,
) -> Result<ConfigOverrides, ConfigError> {
    async {
        let file_content = fs::read_to_string(file_name).await?;

        let overrides = parse_config_overrides(&file_content).await?;

        Ok(overrides)
    }
    .await
    .map_err(|e| ConfigError {
        file: file_name.into(),
        kind: e,
    })
}

pub async fn read_signing_config_overrides(
    file_name: &str,
) -> Result<PartialSigningConfig, ConfigError> {
    async {
        let file_content = fs::read_to_string(file_name).await?;

        let overrides = parse_signing_config_overrides(&file_content).await?;

        Ok(overrides)
    }
    .await
    .map_err(|e| ConfigError {
        file: file_name.into(),
        kind: e,
    })
}

async fn parse_log_config(
    opts: &CliOptions,
    file_content: &str,
) -> Result<LogConfig, ConfigErrorKind> {
    let log_config = parse_partial_log_config(file_content).await?;

    let log_destination = opts.log_destination.or(log_config.log_destination).unwrap_or_default();
    let log_level = opts.log_level.or(log_config.log_level).unwrap_or_default();
    let syslog_facility = opts.syslog_facility.or(log_config.syslog_facility).unwrap_or_default();

    Ok(LogConfig {
        log_destination,
        log_level,
        syslog_facility,
    })
}

async fn parse_partial_log_config(
    file_content: &str,
) -> Result<PartialLogConfig, ConfigErrorKind> {
    let mut config = PartialLogConfig::default();

    let mut keys_seen = HashSet::new();

    for entry in iter_params(file_content) {
        let Entry { key: k, value: v, ln: num } = entry?;

        if keys_seen.contains(k) {
            let kind = ParseParamError::DuplicateKey(k.into());
            return Err(ParseConfigError::new(num, kind).into());
        }

        let inserted_param = parse_log_config_param(&mut config, k, v)
            .map_err(|e| ParseConfigError::new(num, e))?;

        if !inserted_param {
            continue;  // ignore params not related to logging
        }

        keys_seen.insert(k);
    }

    Ok(config)
}

async fn parse_config_overrides(
    file_content: &str,
) -> Result<ConfigOverrides, ParseConfigError> {
    let mut signing_config = PartialSigningConfig::default();
    let mut verification_config = PartialVerificationConfig::default();

    let mut keys_seen = HashSet::new();

    for entry in iter_params(file_content) {
        let Entry { key: k, value: v, ln: num } = entry?;

        if keys_seen.contains(k) {
            let kind = ParseParamError::DuplicateKey(k.into());
            return Err(ParseConfigError::new(num, kind));
        }

        let mut inserted_param = parse_signing_config_param(&mut signing_config, k, v)
            .map_err(|e| ParseConfigError::new(num, e))?;

        if !inserted_param {
            inserted_param = parse_verification_config_param(&mut verification_config, k, v)
                .map_err(|e| ParseConfigError::new(num, e))?;
        }

        if !inserted_param {
            return Err(ParseConfigError::new(num, ParseParamError::UnknownKey(k.into())));
        }

        keys_seen.insert(k);
    }

    Ok(ConfigOverrides {
        signing_config,
        verification_config,
    })
}

async fn parse_signing_config_overrides(
    file_content: &str,
) -> Result<PartialSigningConfig, ParseConfigError> {
    let mut signing_config = PartialSigningConfig::default();

    let mut keys_seen = HashSet::new();

    for entry in iter_params(file_content) {
        let Entry { key: k, value: v, ln: num } = entry?;

        if keys_seen.contains(k) {
            let kind = ParseParamError::DuplicateKey(k.into());
            return Err(ParseConfigError::new(num, kind));
        }

        let inserted_param = parse_signing_config_param(&mut signing_config, k, v)
            .map_err(|e| ParseConfigError::new(num, e))?;

        if !inserted_param {
            return Err(ParseConfigError::new(num, ParseParamError::UnknownKey(k.into())));
        }

        keys_seen.insert(k);
    }

    Ok(signing_config)
}

pub struct Entry<'a> {
    pub ln: usize,
    pub key: &'a str,
    pub value: &'a str,
}

fn iter_params(file_content: &str) -> impl Iterator<Item = Result<Entry<'_>, ParseConfigError>> {
    lines(file_content).map(|(num, line)| match line.split_once('=') {
        Some((k, v)) => Ok(Entry {
            ln: num,
            key: k.trim(),
            value: v.trim(),
        }),
        None => Err(ParseConfigError::new(num, ParseParamError::InvalidLine)),
    })
}

async fn parse_config(
    opts: &CliOptions,
    file_content: &str,
) -> Result<Config, ConfigErrorKind> {
    let raw_config = parse_raw_config(file_content).await?;

    let config = build_config(opts, raw_config).await?;

    Ok(config)
}

async fn parse_raw_config(file_content: &str) -> Result<RawConfig, ConfigErrorKind> {
    let mut config = RawConfig::default();

    let mut keys_seen = HashSet::new();

    for entry in iter_params(file_content) {
        let Entry { key: k, value: v, ln: num } = entry?;

        if keys_seen.contains(k) {
            let kind = ParseParamError::DuplicateKey(k.into());
            return Err(ParseConfigError::new(num, kind).into());
        }

        match k {
            "socket" => {
                let value = Socket::from_str(v).map_err(|_| {
                    ParseConfigError::new(num, ParseParamError::InvalidSocket(v.into()))
                })?;
                config.socket = Some(value);
            }
            "signing_keys" => {
                config.signing_keys_file = Some((num, v.into()));
            }
            "signing_senders" => {
                config.signing_senders_file = Some((num, v.into()));
            }
            "connection_overrides" => {
                config.connection_overrides_file = Some((num, v.into()));
            }
            "recipient_overrides" => {
                config.recipient_overrides_file = Some((num, v.into()));
            }
            "delete_incoming_authentication_results" => {
                let value = params::parse_boolean(v).map_err(|e| ParseConfigError::new(num, e))?;
                config.delete_incoming_authentication_results = Some(value);
            }
            "trust_authenticated_senders" => {
                let value = params::parse_boolean(v).map_err(|e| ParseConfigError::new(num, e))?;
                config.trust_authenticated_senders = Some(value);
            }
            "trusted_networks" => {
                let value = params::parse_trusted_networks(v).map_err(|e| ParseConfigError::new(num, e))?;
                config.trusted_networks = Some(value);
            }
            "authserv_id" => {
                // TODO validate authserv-id ?
                config.authserv_id = Some(v.to_owned());
            }
            "mode" => {
                let value = OperationMode::from_str(v).map_err(|_| {
                    ParseConfigError::new(num, ParseParamError::InvalidMode(v.into()))
                })?;
                config.mode = Some(value);
            }
            "dry_run" => {
                let value = params::parse_boolean(v).map_err(|e| ParseConfigError::new(num, e))?;
                config.dry_run = Some(value);
            }
            _ => {
                let mut inserted_param;

                inserted_param = parse_log_config_param(&mut config.log_config, k, v)
                    .map_err(|e| ParseConfigError::new(num, e))?;

                if !inserted_param {
                    inserted_param = parse_signing_config_param(&mut config.signing_config, k, v)
                        .map_err(|e| ParseConfigError::new(num, e))?;
                }

                if !inserted_param {
                    inserted_param = parse_verification_config_param(&mut config.verification_config, k, v)
                        .map_err(|e| ParseConfigError::new(num, e))?;
                }

                if !inserted_param {
                    return Err(
                        ParseConfigError::new(num, ParseParamError::UnknownKey(k.into())).into(),
                    );
                }
            }
        }

        keys_seen.insert(k);
    }

    Ok(config)
}

async fn build_config(
    opts: &CliOptions,
    raw_config: RawConfig,
) -> Result<Config, ConfigErrorKind> {
    let socket = match opts.socket.as_ref() {
        Some(s) => s.to_owned(),
        None => raw_config.socket.ok_or(ValidationError::MissingSocketParam)?,
    };

    let log_destination = opts.log_destination.or(raw_config.log_config.log_destination).unwrap_or_default();
    let log_level = opts.log_level.or(raw_config.log_config.log_level).unwrap_or_default();
    let syslog_facility = opts.syslog_facility.or(raw_config.log_config.syslog_facility).unwrap_or_default();

    let log_config = LogConfig {
        log_destination,
        log_level,
        syslog_facility,
    };

    let signing_senders = match (raw_config.signing_keys_file, raw_config.signing_senders_file) {
        (Some(signing_keys_file), Some(signing_senders_file)) => {
            read_signing_config(&signing_keys_file, &signing_senders_file).await?
        }
        (None, None) => Default::default(),
        _ => {
            return Err(ValidationError::UnusableSigningConfig.into());
        }
    };

    let connection_overrides = match raw_config.connection_overrides_file {
        Some(connection_overrides_file) => {
            let overrides = tables::read_connection_overrides_table(&connection_overrides_file.1)
                .await
                .map_err(|e| ParseConfigError::new(
                    connection_overrides_file.0,
                    ParseParamError::ReadConnectionOverrides(e),
                ))?;
            Some(overrides)
        }
        None => None,
    };

    let recipient_overrides = match raw_config.recipient_overrides_file {
        Some(recipient_overrides_file) => {
            let overrides = tables::read_recipient_overrides_table(&recipient_overrides_file.1)
                .await
                .map_err(|e| ParseConfigError::new(
                    recipient_overrides_file.0,
                    ParseParamError::ReadRecipientOverrides(e),
                ))?;
            Some(overrides)
        }
        None => None,
    };

    let mode = raw_config.mode.unwrap_or_default();

    let delete_incoming_authentication_results = raw_config.delete_incoming_authentication_results.unwrap_or(true);
    let trust_authenticated_senders = raw_config.trust_authenticated_senders.unwrap_or(true);
    let trusted_networks = raw_config.trusted_networks.unwrap_or_default();

    let dry_run = opts.dry_run || raw_config.dry_run.unwrap_or(false);

    let signing_config = raw_config.signing_config.into_signing_config()
        .map_err(|_| ValidationError::IncompatibleSigningConfigOverrides)?;
    let verification_config = raw_config.verification_config.into_verification_config();

    let config = Config {
        authserv_id: raw_config.authserv_id,
        connection_overrides,
        delete_incoming_authentication_results,
        dry_run,
        log_config,
        mode,
        recipient_overrides,
        signing_config,
        signing_senders,
        socket,
        trust_authenticated_senders,
        trusted_networks,
        verification_config,
    };

    Ok(config)
}

fn parse_log_config_param(
    config: &mut PartialLogConfig,
    k: &str,
    v: &str,
) -> Result<bool, ParseParamError> {
    match k {
        "log_destination" => {
            let value = LogDestination::from_str(v)
                .map_err(|_| ParseParamError::InvalidLogDestination(v.into()))?;
            config.log_destination = Some(value);
        }
        "log_level" => {
            let value = LogLevel::from_str(v)
                .map_err(|_| ParseParamError::InvalidLogLevel(v.into()))?;
            config.log_level = Some(value);
        }
        "syslog_facility" => {
            let value = SyslogFacility::from_str(v)
                .map_err(|_| ParseParamError::InvalidSyslogFacility(v.into()))?;
            config.syslog_facility = Some(value);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn parse_signing_config_param(
    config: &mut PartialSigningConfig,
    k: &str,
    v: &str,
) -> Result<bool, ParseParamError> {
    match k {
        "default_signed_headers" => {
            let value = params::parse_default_signed_headers(v)?;
            config.default_signed_headers = Some(value.into());
        }
        "default_unsigned_headers" => {
            let value = params::parse_default_unsigned_headers(v)?;
            config.default_unsigned_headers = Some(value.into());
        }
        "signed_headers" => {
            let value = params::parse_signed_headers(v)?;
            config.signed_headers = Some(value.into());
        }
        "oversigned_headers" => {
            let value = params::parse_oversigned_headers(v)?;
            config.oversigned_headers = Some(value.into());
        }
        "hash_algorithm" => {
            let value = params::parse_hash_algorithm(v)?;
            config.hash_algorithm = Some(value);
        }
        "canonicalization" => {
            let value = Canonicalization::from_str(v)
                .map_err(|_| ParseParamError::InvalidCanonicalization(v.into()))?;
            config.canonicalization = Some(value);
        }
        "expire_after" => {
            let value = params::parse_expiration(v)?;
            config.expire_after = Some(value);
        }
        "copy_headers" => {
            let value = params::parse_boolean(v)?;
            config.copy_headers = Some(value);
        }
        "limit_body_length" => {
            let value = params::parse_boolean(v)?;
            config.limit_body_length = Some(value);
        }
        "request_reports" => {
            let value = params::parse_boolean(v)?;
            config.request_reports = Some(value);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn parse_verification_config_param(
    config: &mut PartialVerificationConfig,
    k: &str,
    v: &str,
) -> Result<bool, ParseParamError> {
    match k {
        "allow_expired" => {
            let value = params::parse_boolean(v)?;
            config.allow_expired = Some(value);
        }
        "min_rsa_key_bits" => {
            let value = params::parse_u32_as_usize(v)?;
            config.min_rsa_key_bits = Some(value);
        }
        "allow_sha1" => {
            let value = params::parse_boolean(v)?;
            config.allow_sha1 = Some(value);
        }
        "allow_timestamp_in_future" => {
            let value = params::parse_boolean(v)?;
            config.allow_timestamp_in_future = Some(value);
        }
        "forbid_unsigned_content" => {
            let value = params::parse_boolean(v)?;
            config.forbid_unsigned_content = Some(value);
        }
        "lookup_timeout" => {
            let value = params::parse_duration_secs(v)?;
            config.lookup_timeout = Some(value);
        }
        "max_signatures" => {
            let value = params::parse_u32_as_usize(v)?;
            config.max_signatures = Some(value);
        }
        "reject_failures" => {
            let value = params::parse_reject_failures(v)?;
            config.reject_failures = Some(value.into());
        }
        "required_signed_headers" => {
            let value = params::parse_qualified_field_names(v)?;
            config.required_signed_headers = Some(value.into());
        }
        "time_tolerance" => {
            let value = params::parse_duration_secs(v)?;
            config.time_tolerance = Some(value);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub fn lines(s: &str) -> impl Iterator<Item = (usize, &str)> {
    s.lines().enumerate().filter_map(|(i, line)| {
        if is_ignored_line(line) {
            None
        } else {
            Some((i + 1, line.trim()))
        }
    })
}

fn is_ignored_line(line: &str) -> bool {
    let line = line.trim_start();
    line.is_empty() || line.starts_with('#')
}
