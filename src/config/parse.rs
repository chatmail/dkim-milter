use crate::config::{
    model::{
        self, LogConfig, LogDestination, LogLevel, OperationMode, OverrideEntry, Expiration, OversignedHeaders,
        ParseSignedHeaders, SignedFieldName, SignedHeaders, SigningConfig, SigningConfigOverrides,
        Socket, VerificationConfig,
    },
    read, CliOptions, Config, ConfigError, ConfigErrorKind,
};
use regex::Regex;
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::{self, Display, Formatter},
    io,
    path::PathBuf,
    str::FromStr,
};
use viadkim::{
    crypto::{HashAlgorithm, SigningKey},
    signature::{Canonicalization, DomainName, Selector},
};

#[derive(Debug)]
pub enum ValidationError {
    MissingSocketParam,
    UnusableSigningConfig,
}

impl Error for ValidationError {}

impl Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSocketParam => write!(f, "missing mandatory socket parameter"),
            Self::UnusableSigningConfig => write!(f, "unusable signing senders and/or keys configuration"),
        }
    }
}

#[derive(Debug)]
pub struct ParseConfigError {
    pub line: usize,
    pub kind: ParseParamError,
}

impl Error for ParseConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use ParseParamError::*;

        match &self.kind {
            InvalidLine
            | UnknownSection(_)
            | MissingSection(_)
            | UnknownKey(_)
            | DuplicateKey(_)
            | InvalidLogDestination(_)
            | InvalidLogLevel(_)
            | InvalidSocket(_)
            | InvalidBoolean(_)
            | InvalidSignedHeaders(_)
            | SignedHeadersMissingFrom(_)
            | FromInUnsignedHeaders(_)
            | InvalidHashAlgorithm(_)
            | InvalidCanonicalization(_)
            | InvalidExpiration(_)
            | InvalidMode(_) => None,
            ReadSigningKeys(e) | ReadSigningSenders(e) | ReadRecipientOverrides(e) => Some(e),
        }
    }
}

impl Display for ParseConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use ParseParamError::*;

        write!(f, "parse error at line {}", self.line)?;

        match &self.kind {
            InvalidLine
            | UnknownSection(_)
            | MissingSection(_)
            | UnknownKey(_)
            | DuplicateKey(_)
            | InvalidLogDestination(_)
            | InvalidLogLevel(_)
            | InvalidSocket(_)
            | InvalidBoolean(_)
            | InvalidSignedHeaders(_)
            | SignedHeadersMissingFrom(_)
            | FromInUnsignedHeaders(_)
            | InvalidHashAlgorithm(_)
            | InvalidCanonicalization(_)
            | InvalidExpiration(_)
            | InvalidMode(_) => write!(f, ": {}", self.kind),
            _ => Ok(()),
        }
    }
}

// TODO rename *Kind?
#[derive(Debug)]
pub enum ParseParamError {
    InvalidLine,
    UnknownSection(String),
    MissingSection(String),  // if section is expected but missing (eg [signing] in overrides file)
    UnknownKey(String),
    DuplicateKey(String),

    InvalidLogDestination(String),
    InvalidLogLevel(String),

    InvalidSocket(String),
    InvalidBoolean(String),
    InvalidSignedHeaders(String),
    SignedHeadersMissingFrom(String),
    FromInUnsignedHeaders(String),
    InvalidHashAlgorithm(String),
    InvalidCanonicalization(String),
    InvalidExpiration(String),
    InvalidMode(String),

    ReadSigningKeys(TableError),
    ReadSigningSenders(TableError),
    ReadRecipientOverrides(TableError),
}

impl Error for ParseParamError {}

impl Display for ParseParamError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // TODO move?
        match self {
            Self::InvalidLine => write!(f, "invalid line syntax"),
            Self::UnknownSection(section) => write!(f, "unknown section \"{section}\""),
            Self::MissingSection(section) => write!(f, "missing section \"{section}\""),
            Self::UnknownKey(key) => write!(f, "unknown parameter \"{key}\""),
            Self::DuplicateKey(key) => write!(f, "duplicate parameter \"{key}\""),

            Self::InvalidLogDestination(s) => write!(f, "invalid log destination \"{s}\""),
            Self::InvalidLogLevel(s) => write!(f, "invalid log level \"{s}\""),

            Self::InvalidSocket(s) => write!(f, "invalid socket \"{s}\""),
            Self::InvalidBoolean(s) => write!(f, "invalid Boolean value \"{s}\""),
            Self::InvalidSignedHeaders(s) => write!(f, "invalid signed headers \"{s}\""),
            Self::SignedHeadersMissingFrom(_s) => write!(f, "signed headers are missing required header From"),
            Self::FromInUnsignedHeaders(_s) => write!(f, "unsigned headers contain required header From"),
            Self::InvalidHashAlgorithm(s) => write!(f, "invalid hash algorithm \"{s}\""),
            Self::InvalidCanonicalization(s) => write!(f, "invalid canonicalization \"{s}\""),
            Self::InvalidExpiration(s) => write!(f, "invalid expiration duration \"{s}\""),
            Self::InvalidMode(s) => write!(f, "invalid operation mode \"{s}\""),

            Self::ReadSigningKeys(_) => write!(f, "failed to read signing keys"),
            Self::ReadSigningSenders(_) => write!(f, "failed to read signing senders"),
            Self::ReadRecipientOverrides(_) => write!(f, "failed to read recipient overrides"),
        }
    }
}

#[derive(Debug)]
pub struct TableError {
    pub file: PathBuf,
    pub kind: TableErrorKind,
}

impl TableError {
    pub fn new(file: impl Into<PathBuf>, kind: TableErrorKind) -> Self {
        Self {
            file: file.into(),
            kind,
        }
    }
}

impl Error for TableError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            TableErrorKind::Io(e) => Some(e),
            TableErrorKind::Format(e) => Some(e),
        }
    }
}

impl Display for TableError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to read table from {}", self.file.display())
    }
}

#[derive(Debug)]
pub enum TableErrorKind {
    Io(io::Error),
    Format(TableFormatError),
}

// TODO delete?
impl Display for TableErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => write!(f, "I/O error"),
            Self::Format(_) => write!(f, "error parsing table"),
        }
    }
}

impl From<io::Error> for TableErrorKind {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<TableFormatError> for TableErrorKind {
    fn from(error: TableFormatError) -> Self {
        Self::Format(error)
    }
}

// format error at line <n>: <error> (unless has source error)
#[derive(Debug)]
pub struct TableFormatError {
    pub line: usize,
    pub kind: TableFormatErrorKind,
}

impl TableFormatError {
    pub fn new(line: usize, kind: TableFormatErrorKind) -> Self {
        Self { line, kind }
    }
}

impl Error for TableFormatError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use TableFormatErrorKind::*;

        match &self.kind {
            InvalidLine
            | TooManyFields
            | InvalidExpr
            | InvalidDomain
            | InvalidSelector
            | InvalidFileSyntax => None,
            ReadKeyFile(e) => Some(e),
            ReadConfig(e) => Some(e),
        }
    }
}

impl Display for TableFormatError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use TableFormatErrorKind::*;

        write!(f, "format error at line {}", self.line)?;

        match &self.kind {
            InvalidLine
            | TooManyFields
            | InvalidExpr
            | InvalidDomain
            | InvalidSelector
            | InvalidFileSyntax => write!(f, ": {}", self.kind),
            _ => Ok(()),
        }
    }
}

#[derive(Debug)]
pub enum TableFormatErrorKind {
    InvalidLine,
    TooManyFields,
    InvalidExpr,
    InvalidDomain,
    InvalidSelector,
    InvalidFileSyntax,
    ReadKeyFile(io::Error),
    ReadConfig(Box<ConfigError>),  // recursive, but never more than one level
}

impl Display for TableFormatErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // TODO move?
        match self {
            Self::InvalidLine => write!(f, "invalid line syntax"),
            Self::TooManyFields => write!(f, "too many fields in line"),
            Self::InvalidExpr => write!(f, "invalid match expression"),
            Self::InvalidDomain => write!(f, "invalid domain"),
            Self::InvalidSelector => write!(f, "invalid selector"),
            Self::InvalidFileSyntax => write!(f, "invalid included file syntax"),
            Self::ReadKeyFile(_) => write!(f, "invalid included key file"),
            Self::ReadConfig(_) => write!(f, "invalid included configuration"),
        }
    }
}

// TODO this is an inaccurate preliminary parse of the log configuration only
pub async fn parse_log_config(
    opts: &CliOptions,
    file_content: &str,
) -> Result<LogConfig, ConfigErrorKind> {
    let mut log_destination = None;
    let mut log_level = None;

    let mut keys_seen = HashSet::new();

    let mut iter = lines(file_content);

    while let Some((num, line)) = iter.next() {
        // bail on first section seen
        if let Some(_section) = parse_section_line(line) {
            break;
        }

        match line.split_once('=') {
            Some((k, v)) => {
                let k = k.trim();
                let v = v.trim();

                if keys_seen.contains(k) {
                    return Err(ParseConfigError {
                        line: num,
                        kind: ParseParamError::DuplicateKey(k.into()),
                    }
                    .into());
                }

                match k {
                    "log_destination" => {
                        let value = LogDestination::from_str(v).map_err(|_| ParseConfigError {
                            line: num,
                            kind: ParseParamError::InvalidLogDestination(v.into()),
                        })?;
                        log_destination = Some(value);
                    }
                    "log_level" => {
                        let value = LogLevel::from_str(v).map_err(|_| ParseConfigError {
                            line: num,
                            kind: ParseParamError::InvalidLogLevel(v.into()),
                        })?;
                        log_level = Some(value);
                    }
                    _ => {
                        // ignore all other params
                        continue;
                    }
                }

                keys_seen.insert(k);
            }
            None => {
                return Err(ParseConfigError {
                    line: num,
                    kind: ParseParamError::InvalidLine,
                }
                .into());
            }
        }
    }

    let log_destination = opts.log_destination.or(log_destination).unwrap_or_default();
    let log_level = opts.log_level.or(log_level).unwrap_or_default();

    Ok(LogConfig {
        log_destination,
        log_level,
    })
}

pub async fn parse_config(
    opts: &CliOptions,
    file_content: &str,
) -> Result<Config, ConfigErrorKind> {
    let mut authserv_id = None;
    let mut mode = None;
    let mut signing_keys_file = None;
    let mut signing_senders_file = None;
    let mut recipient_overrides_file = None;
    let mut socket = None;
    let mut fail_if_expired = None;
    let mut log_destination = None;
    let mut log_level = None;

    let mut signing_config = None;
    let mut verification_config = None;

    let mut keys_seen = HashSet::new();

    let mut iter = lines(file_content);

    while let Some((num, line)) = iter.next() {
        if let Some(section) = parse_section_line(line) {
            let mut next_section = Some(section.to_owned());

            // TODO duplicate sections

            while let Some(section) = next_section {
                match section.as_str() {
                    "signing" => {
                        let (c, next) = parse_config_section_signing(&mut iter).await?;
                        signing_config = Some(c);
                        next_section = next;
                    }
                    "verification" => {
                        let (c, next) = parse_config_section_verification(&mut iter).await?;
                        verification_config = Some(c);
                        next_section = next;
                    }
                    _ => {
                        return Err(ParseConfigError {
                            line: num,
                            kind: ParseParamError::UnknownSection(section),
                        }
                        .into());
                    }
                }
            }

            break;
        }

        match line.split_once('=') {
            Some((k, v)) => {
                let k = k.trim();
                let v = v.trim();

                if keys_seen.contains(k) {
                    return Err(ParseConfigError {
                        line: num,
                        kind: ParseParamError::DuplicateKey(k.into()),
                    }
                    .into());
                }

                match k {
                    "socket" => {
                        let value = Socket::from_str(v).map_err(|_| ParseConfigError {
                            line: num,
                            kind: ParseParamError::InvalidSocket(v.into()),
                        })?;
                        socket = Some(value);
                    }
                    "signing_keys" => {
                        signing_keys_file = Some((num, v));
                    }
                    "signing_senders" => {
                        signing_senders_file = Some((num, v));
                    }
                    "recipient_overrides" => {
                        recipient_overrides_file = Some((num, v));
                    }
                    "authserv_id" => {
                        authserv_id = Some(v.to_owned());
                    }
                    "log_destination" => {
                        let value = LogDestination::from_str(v).map_err(|_| ParseConfigError {
                            line: num,
                            kind: ParseParamError::InvalidLogDestination(v.into()),
                        })?;
                        log_destination = Some(value);
                    }
                    "log_level" => {
                        let value = LogLevel::from_str(v).map_err(|_| ParseConfigError {
                            line: num,
                            kind: ParseParamError::InvalidLogLevel(v.into()),
                        })?;
                        log_level = Some(value);
                    }
                    "mode" => {
                        let value = OperationMode::from_str(v).map_err(|_| ParseConfigError {
                            line: num,
                            kind: ParseParamError::InvalidMode(v.into()),
                        })?;
                        mode = Some(value);
                    }
                    "fail_if_expired" => {
                        let value = parse_boolean(v).map_err(|_| ParseConfigError {
                            line: num,
                            kind: ParseParamError::InvalidBoolean(v.into()),
                        })?;
                        fail_if_expired = Some(value);
                    }
                    _ => {
                        return Err(ParseConfigError {
                            line: num,
                            kind: ParseParamError::UnknownKey(k.into()),
                        }
                        .into());
                    }
                }

                keys_seen.insert(k);
            }
            None => {
                return Err(ParseConfigError {
                    line: num,
                    kind: ParseParamError::InvalidLine,
                }
                .into());
            }
        }
    }

    let socket = match opts.socket.as_ref() {
        Some(s) => s.to_owned(),
        None => socket.ok_or(ValidationError::MissingSocketParam)?,
    };

    let log_destination = opts.log_destination.or(log_destination).unwrap_or_default();
    let log_level = opts.log_level.or(log_level).unwrap_or_default();

    let log_config = LogConfig {
        log_destination,
        log_level,
    };

    let signing_senders = match (signing_keys_file, signing_senders_file) {
        (Some(signing_keys_file), Some(signing_senders_file)) => {
            read::read_signing_config(signing_keys_file, signing_senders_file).await?
        }
        (None, None) => Default::default(),
        _ => {
            return Err(ValidationError::UnusableSigningConfig.into());
        }
    };

    let recipient_overrides = match recipient_overrides_file {
        Some(recipient_overrides_file) => {
            let overrides = read::read_recipient_overrides_table(recipient_overrides_file.1)
                .await
                .map_err(|e| ParseConfigError {
                    line: recipient_overrides_file.0,
                    kind: ParseParamError::ReadRecipientOverrides(e),
                })?;
            Some(overrides)
        }
        None => None,
    };

    let mode = mode.unwrap_or_default();

    let fail_if_expired = fail_if_expired.unwrap_or(true);

    let signing_config = signing_config.unwrap_or_default();
    let verification_config = verification_config.unwrap_or_default();

    let config = Config {
        socket,
        signing_senders,
        recipient_overrides,
        authserv_id,
        log_config,
        signing_config,
        verification_config,
        mode,
        fail_if_expired,
    };

    Ok(config)
}

async fn parse_config_section_signing(
    iter: &mut impl Iterator<Item = (usize, &str)>,
) -> Result<(SigningConfig, Option<String>), ParseConfigError> {
    let (config, next) = parse_config_section_signing_overrides(iter).await?;

    let config = config.into_signing_config();

    Ok((config, next))
}

async fn parse_config_section_signing_overrides(
    iter: &mut impl Iterator<Item = (usize, &str)>,
) -> Result<(SigningConfigOverrides, Option<String>), ParseConfigError> {
    let mut default_signed_headers = None;
    let mut default_unsigned_headers = None;
    let mut signed_headers = None;
    let mut oversigned_headers = None;
    let mut hash_algorithm = None;
    let mut canonicalization = None;
    let mut expire_after = None;
    let mut copy_headers = None;
    let mut limit_body_length = None;

    let mut next_section = None;

    let mut keys_seen = HashSet::new();

    while let Some((num, line)) = iter.next() {
        if let Some(section) = parse_section_line(line) {
            next_section = Some(section.into());
            break;
        }

        match line.split_once('=') {
            Some((k, v)) => {
                let k = k.trim();
                let v = v.trim();

                if keys_seen.contains(k) {
                    return Err(ParseConfigError {
                        line: num,
                        kind: ParseParamError::DuplicateKey(k.into()),
                    });
                }

                match k {
                    "default_signed_headers" => {
                        let value: Vec<_> = model::split_at_colon(v)
                            .map(|s| {
                                s.and_then(|s| SignedFieldName::new(s).map_err(|_| ParseSignedHeaders))
                            })
                            .collect::<Result<_, _>>()
                            .map_err(|_| ParseConfigError {
                                line: num,
                                kind: ParseParamError::InvalidSignedHeaders(v.into()),
                            })?;
                        if !value.iter().any(|n| *n.as_ref() == "From") {
                            return Err(ParseConfigError {
                                line: num,
                                kind: ParseParamError::SignedHeadersMissingFrom(v.into()),
                            });
                        }
                        default_signed_headers = Some(value);
                    }
                    "default_unsigned_headers" => {
                        let value: Vec<_> = model::split_at_colon(v)
                            .map(|s| {
                                s.and_then(|s| SignedFieldName::new(s).map_err(|_| ParseSignedHeaders))
                            })
                            .collect::<Result<_, _>>()
                            .map_err(|_| ParseConfigError {
                                line: num,
                                kind: ParseParamError::InvalidSignedHeaders(v.into()),
                            })?;
                        if value.iter().any(|n| *n.as_ref() == "From") {
                            return Err(ParseConfigError {
                                line: num,
                                kind: ParseParamError::FromInUnsignedHeaders(v.into()),
                            });
                        }
                        default_unsigned_headers = Some(value);
                    }
                    "signed_headers" => {
                        let value =
                            SignedHeaders::from_str(v).map_err(|_| ParseConfigError {
                                line: num,
                                kind: ParseParamError::InvalidSignedHeaders(v.into()),
                            })?;
                        signed_headers = Some(value);
                    }
                    "oversigned_headers" => {
                        let value =
                            OversignedHeaders::from_str(v).map_err(|_| ParseConfigError {
                                line: num,
                                kind: ParseParamError::InvalidSignedHeaders(v.into()),
                            })?;
                        oversigned_headers = Some(value);
                    }
                    "hash_algorithm" => {
                        let value = match v {
                            "sha256" => HashAlgorithm::Sha256,
                            #[cfg(feature = "sha1")]
                            "sha1" => HashAlgorithm::Sha1,
                            _ => {
                                return Err(ParseConfigError {
                                    line: num,
                                    kind: ParseParamError::InvalidHashAlgorithm(v.into()),
                                });
                            }
                        };
                        hash_algorithm = Some(value);
                    }
                    "canonicalization" => {
                        let value =
                            Canonicalization::from_str(v).map_err(|_| ParseConfigError {
                                line: num,
                                kind: ParseParamError::InvalidCanonicalization(v.into()),
                            })?;
                        canonicalization = Some(value);
                    }
                    "expire_after" => {
                        let value =
                            Expiration::from_str(v).map_err(|_| ParseConfigError {
                                line: num,
                                kind: ParseParamError::InvalidExpiration(v.into()),
                            })?;
                        expire_after = Some(value);
                    }
                    "copy_headers" => {
                        let value = parse_boolean(v).map_err(|_| ParseConfigError {
                            line: num,
                            kind: ParseParamError::InvalidBoolean(v.into()),
                        })?;
                        copy_headers = Some(value);
                    }
                    "limit_body_length" => {
                        let value = parse_boolean(v).map_err(|_| ParseConfigError {
                            line: num,
                            kind: ParseParamError::InvalidBoolean(v.into()),
                        })?;
                        limit_body_length = Some(value);
                    }
                    _ => {
                        return Err(ParseConfigError {
                            line: num,
                            kind: ParseParamError::UnknownKey(k.into()),
                        });
                    }
                }

                keys_seen.insert(k);
            }
            None => {
                return Err(ParseConfigError {
                    line: num,
                    kind: ParseParamError::InvalidLine,
                });
            }
        }
    }

    let signing_config = SigningConfigOverrides {
        default_signed_headers,
        default_unsigned_headers,
        signed_headers,
        oversigned_headers,
        hash_algorithm,
        canonicalization,
        expire_after,
        copy_headers,
        limit_body_length,
    };

    Ok((signing_config, next_section))
}

async fn parse_config_section_verification(
    iter: &mut impl Iterator<Item = (usize, &str)>,
) -> Result<(VerificationConfig, Option<String>), ParseConfigError> {
    let mut next_section = None;

    let mut keys_seen = HashSet::new();

    while let Some((num, line)) = iter.next() {
        if let Some(section) = parse_section_line(line) {
            next_section = Some(section.into());
            break;
        }

        match line.split_once('=') {
            Some((k, v)) => {
                let k = k.trim();
                let _v = v.trim();

                if keys_seen.contains(k) {
                    return Err(ParseConfigError {
                        line: num,
                        kind: ParseParamError::DuplicateKey(k.into()),
                    });
                }

                match k {
                    "reject_results" => {
                        if true {
                            todo!();
                        }
                    }
                    _ => {
                        return Err(ParseConfigError {
                            line: num,
                            kind: ParseParamError::UnknownKey(k.into()),
                        });
                    }
                }

                keys_seen.insert(k);
            }
            None => {
                return Err(ParseConfigError {
                    line: num,
                    kind: ParseParamError::InvalidLine,
                });
            }
        }
    }

    let verification_config = VerificationConfig { };

    Ok((verification_config, next_section))
}

#[derive(Debug)]
pub struct TempSenderEntry {
    pub sender_expr: Regex,
    pub domain: DomainName,
    pub selector: Selector,
    pub key_name: String,
    pub signing_config: Option<SigningConfigOverrides>,
}

pub async fn parse_signing_senders_table(
    file_content: &str,
) -> Result<Vec<TempSenderEntry>, TableFormatError> {
    let mut entries = vec![];

    let iter = lines(file_content);

    for (num, line) in iter {
        let mut iter = line.split_ascii_whitespace();

        let sender_expr = iter
            .next()
            .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidLine))?;
        let domain = iter
            .next()
            .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidLine))?;
        let selector = iter
            .next()
            .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidLine))?;
        let key_name = iter
            .next()
            .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidLine))?;

        let sig_config_file = iter.next();

        if sig_config_file.is_some() {
            if iter.next().is_some() {
                return Err(TableFormatError::new(
                    num,
                    TableFormatErrorKind::TooManyFields,
                ));
            }
        }

        let sender_expr = parse_sender_expr(sender_expr)
            .map_err(|_| TableFormatError::new(num, TableFormatErrorKind::InvalidExpr))?;
        let domain = DomainName::new(domain)
            .map_err(|_| TableFormatError::new(num, TableFormatErrorKind::InvalidDomain))?;
        let selector = Selector::new(selector)
            .map_err(|_| TableFormatError::new(num, TableFormatErrorKind::InvalidSelector))?;

        let signing_config = match sig_config_file {
            Some(sig_config_file) => {
                let sig_config_file = sig_config_file
                    .trim()
                    .strip_prefix('<')
                    .ok_or_else(|| {
                        TableFormatError::new(num, TableFormatErrorKind::InvalidFileSyntax)
                    })?
                    .trim();

                let config = read::read_signing_config_overrides(sig_config_file)
                    .await
                    .map_err(|e| {
                        TableFormatError::new(num, TableFormatErrorKind::ReadConfig(Box::new(e)))
                    })?;

                Some(config)
            }
            None => None,
        };

        let entry = TempSenderEntry {
            sender_expr,
            domain,
            selector,
            key_name: key_name.into(),
            signing_config,
        };

        entries.push(entry);
    }

    Ok(entries)
}

// TODO well-formedness, idna, quoting, case-insensitive
fn parse_sender_expr(s: &str) -> Result<Regex, Box<dyn Error>> {
    if s.contains('@') {
        // this is an email address expr (apply regex to entire address); example:
        // me+*@*.example.com
        let pieces: Vec<_> = s.split('*')
            .map(regex::escape)
            .collect();
        let re = format!("^(?i){}$", &pieces.join(".*"));
        Ok(Regex::new(&re).unwrap())
    } else {
        // this is a domain expr (construct regex that constrains domain)
        if let Some(s) = s.strip_prefix('.') {
            // domain + subdomains shorthand match; example:
            // .example.com
            let domain = DomainName::new(s)?;
            let re = format!("^(?i).*@(.+\\.)?{}$", regex::escape(domain.as_ref()));
            Ok(Regex::new(&re).unwrap())
        } else {
            if let Ok(d) = DomainName::new(s) {
                // exact domain match; example:
                // example.com
                let re = format!("^(?i).*@{}$", regex::escape(d.as_ref()));
                Ok(Regex::new(&re).unwrap())
            } else {
                // try regex; example:
                // sub*.example.com
                let pieces: Vec<_> = s.split('*')
                    .map(regex::escape)
                    .collect();
                let re = format!("^(?i).*@{}$", &pieces.join(".*"));
                Ok(Regex::new(&re).unwrap())
            }
        }
    }
}

pub async fn parse_signing_keys_table(
    file_content: &str,
) -> Result<HashMap<String, SigningKey>, TableFormatError> {
    let mut map = HashMap::new();

    let iter = lines(file_content);

    for (num, line) in iter {
        let mut iter = line.split_ascii_whitespace();

        let (name, value) = match (iter.next(), iter.next(), iter.next()) {
            (Some(name), Some(value), None) => (name, value),
            _ => {
                return Err(TableFormatError::new(
                    num,
                    TableFormatErrorKind::InvalidLine,
                ));
            }
        };

        // TODO duplicate keys

        // TODO for now, require file paths to start with '<'
        let v = value
            .trim()
            .strip_prefix('<')
            .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidFileSyntax))?
            .trim();

        let key = read::read_signing_key(v)
            .await
            .map_err(|e| TableFormatError::new(num, TableFormatErrorKind::ReadKeyFile(e)))?;

        map.insert(name.into(), key);
    }

    Ok(map)
}

pub async fn parse_recipient_overrides_table(
    file_content: &str,
) -> Result<Vec<OverrideEntry>, TableFormatError> {
    let mut entries = vec![];

    let iter = lines(file_content);

    for (num, line) in iter {
        let mut iter = line.split_ascii_whitespace();

        let sender_expr = iter
            .next()
            .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidLine))?;
        let overrides_file = iter
            .next()
            .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidLine))?;

        if iter.next().is_some() {
            return Err(TableFormatError::new(num, TableFormatErrorKind::TooManyFields));
        }

        // TODO
        let expr = parse_sender_expr(sender_expr)
            .map_err(|_| TableFormatError::new(num, TableFormatErrorKind::InvalidExpr))?;

        let v = overrides_file
            .trim()
            .strip_prefix('<')
            .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidFileSyntax))?
            .trim();

        let config = read::read_signing_config_overrides(v).await.map_err(|e| {
            TableFormatError::new(num, TableFormatErrorKind::ReadConfig(Box::new(e)))
        })?;

        let entry = OverrideEntry { expr, config };

        entries.push(entry);
    }

    Ok(entries)
}

pub async fn parse_signing_config_overrides(
    file_content: &str,
) -> Result<SigningConfigOverrides, ParseConfigError> {
    let mut file_lines = lines(file_content);

    // TODO

    let (num, line) = file_lines.next().ok_or_else(|| ParseConfigError {
        line: 0,
        kind: ParseParamError::MissingSection("signing".into()),
    })?;

    if !matches!(parse_section_line(line), Some(s) if s == "signing") {
        return Err(ParseConfigError {
            line: num,
            kind: ParseParamError::UnknownSection(line.into()),
        });
    }

    let (config, _next) = parse_config_section_signing_overrides(&mut file_lines).await?;

    Ok(config)
}

fn parse_section_line(s: &str) -> Option<&str> {
    s.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim)
}

fn lines(s: &str) -> impl Iterator<Item = (usize, &str)> {
    s.lines().enumerate().filter_map(|(i, line)| {
        let line = line.trim();
        if is_ignored_line(line) {
            None
        } else {
            Some((i + 1, line))
        }
    })
}

fn parse_boolean(s: &str) -> Result<bool, ()> {
    match s {
        "yes" | "true" => Ok(true),
        "no" | "false" => Ok(false),
        _ => Err(()),
    }
}

fn is_ignored_line(line: &str) -> bool {
    let line = line.trim_start();
    line.is_empty() || line.starts_with('#')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sender_expr_ok() {
        let expr = parse_sender_expr(".example.org").unwrap();
        assert!(expr.is_match("who@example.org"));
        assert!(expr.is_match("who@mail.example.org"));
        assert!(!expr.is_match("who@.example.org"));
        assert!(!expr.is_match("who@aexample.org"));

        let expr = parse_sender_expr("example.org").unwrap();
        assert!(expr.is_match("who@example.org"));
        assert!(!expr.is_match("who@mail.example.org"));
    }
}
