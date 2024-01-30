// DKIM Milter – milter for DKIM signing and verification
// Copyright © 2024 David Bürgin <dbuergin@gluet.ch>
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
    config::{
        format,
        model::{ConfigOverrides, DomainExpr, PartialSigningConfig},
        ConfigError,
    },
    datastore::{
        self, BoxFuture, ConfigOverridesResult, ConnectionOverridesDb, RecipientOverridesDb,
        SigningKeysDb, SigningKeysResult, SigningSendersDb, SigningSendersResult,
        UnresolvedSenderMatch,
    },
};
use ipnet::IpNet;
use regex::Regex;
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::{self, Display, Formatter},
    io::{self, ErrorKind},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::fs;
use viadkim::{crypto::SigningKey, signature::Selector};

#[derive(Debug)]
pub struct SigningKeyError {
    pub file: PathBuf,
    pub kind: io::Error,
}

impl SigningKeyError {
    pub fn new(file: impl Into<PathBuf>, kind: io::Error) -> Self {
        Self {
            file: file.into(),
            kind,
        }
    }
}

impl Display for SigningKeyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to read signing key from {}", self.file.display())
    }
}

impl Error for SigningKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.kind)
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

impl Display for TableError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let file = self.file.display();
        match &self.kind {
            TableErrorKind::Io(_) => write!(f, "I/O error reading table from {}", file),
            TableErrorKind::Format(_) => write!(f, "wrong format in table at {}", file),
            TableErrorKind::MissingKeyId(key_id) => {
                write!(f, "key ID \"{key_id}\" not found in table at {}", file)
            }
        }
    }
}

impl Error for TableError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            TableErrorKind::Io(e) => Some(e),
            TableErrorKind::Format(e) => Some(e),
            TableErrorKind::MissingKeyId(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum TableErrorKind {
    Io(io::Error),
    Format(TableFormatError),
    MissingKeyId(Arc<str>),
}

impl Display for TableErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => write!(f, "I/O error"),
            Self::Format(_) => write!(f, "error parsing table"),
            Self::MissingKeyId(key_id) => write!(f, "key ID \"{key_id}\" not found in table"),
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

impl Display for TableFormatError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use TableFormatErrorKind::*;

        write!(f, "format error at line {}", self.line)?;

        match &self.kind {
            InvalidLine
            | InvalidDataSource
            | TooManyFields
            | DuplicateKey
            | InvalidSender
            | InvalidDomain
            | InvalidSelector
            | InvalidNetwork
            | InvalidRecipient => write!(f, ": {}", self.kind),
            ReadConfig(_) | ReadKeyFile(_) => Ok(()),
        }
    }
}

impl Error for TableFormatError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use TableFormatErrorKind::*;

        match &self.kind {
            InvalidLine
            | InvalidDataSource
            | TooManyFields
            | DuplicateKey
            | InvalidSender
            | InvalidDomain
            | InvalidSelector
            | InvalidNetwork
            | InvalidRecipient => None,
            ReadConfig(e) => Some(e),
            ReadKeyFile(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub enum TableFormatErrorKind {
    InvalidLine,
    InvalidDataSource,
    TooManyFields,
    DuplicateKey,
    InvalidSender,
    InvalidDomain,
    InvalidSelector,
    InvalidNetwork,
    InvalidRecipient,
    ReadConfig(ConfigError),  // recursive, but never more than one level
    ReadKeyFile(SigningKeyError),
}

impl Display for TableFormatErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLine => write!(f, "invalid line syntax"),
            Self::InvalidDataSource => write!(f, "unsupported or invalid data source prefix"),
            Self::TooManyFields => write!(f, "too many fields in line"),
            Self::DuplicateKey => write!(f, "duplicate key in table with unique keys"),
            Self::InvalidSender => write!(f, "invalid sender expression"),
            Self::InvalidDomain => write!(f, "invalid domain expression"),
            Self::InvalidSelector => write!(f, "invalid selector"),
            Self::InvalidNetwork => write!(f, "invalid network address"),
            Self::InvalidRecipient => write!(f, "invalid recipient expression"),
            Self::ReadConfig(_) => write!(f, "invalid included configuration"),
            Self::ReadKeyFile(_) => write!(f, "invalid included key file"),
        }
    }
}

#[derive(Debug)]
enum FsDataSource<T> {
    Slurp(T),
    File { ln: usize, file: PathBuf },
}

type SigningConfigDataSource = FsDataSource<Arc<PartialSigningConfig>>;

#[derive(Debug)]
struct UnresolvedSigningSender {
    sender_expr: Regex,
    domain: DomainExpr,
    selector: Selector,
    unresolved_key: Arc<str>,
    signing_config: Option<SigningConfigDataSource>,
}

#[derive(Debug)]
struct SlurpSigningSendersDb {
    file: PathBuf,
    entries: Vec<UnresolvedSigningSender>,
}

#[derive(Debug)]
struct FileSigningSendersDb {
    file: PathBuf,
}

pub async fn read_slurp_signing_senders(file: &str) -> Result<impl SigningSendersDb, TableError> {
    let entries = read_signing_senders_table(file).await?;
    Ok(SlurpSigningSendersDb { file: file.into(), entries })
}

pub async fn read_file_signing_senders(file: &str) -> Result<impl SigningSendersDb, TableError> {
    let file = file.into();
    Ok(FileSigningSendersDb { file })
}

impl SigningSendersDb for SlurpSigningSendersDb {
    fn get_cached_key_ids(&self) -> Vec<Arc<str>> {
        let mut keys_seen = HashSet::new();
        self.entries.iter()
            .filter(|e| keys_seen.insert(&e.unresolved_key))
            .map(|e| e.unresolved_key.clone())
            .collect()
    }

    fn find_all(&self, sender: String) -> BoxFuture<'_, SigningSendersResult> {
        Box::pin(async move {
            let matches = find_signing_senders(&self.entries, sender)
                .await
                .map_err(|e| TableError::new(&self.file, e))?;
            Ok(matches)
        })
    }
}

impl SigningSendersDb for FileSigningSendersDb {
    fn find_all(&self, sender: String) -> BoxFuture<'_, SigningSendersResult> {
        Box::pin(async move {
            let matches = scan_signing_senders_table(&self.file, sender).await?;
            Ok(matches)
        })
    }
}

async fn read_signing_senders_table(
    file: &str,
) -> Result<Vec<UnresolvedSigningSender>, TableError> {
    async {
        let file_content = fs::read_to_string(file).await?;
        let entries = parse_signing_senders_table(&file_content).await?;
        Ok(entries)
    }
    .await
    .map_err(|e| TableError::new(file, e))
}

async fn parse_signing_senders_table(
    file_content: &str,
) -> Result<Vec<UnresolvedSigningSender>, TableFormatError> {
    let mut entries = vec![];

    for (ln, s) in format::lines(file_content) {
        let (sender_expr, domain, selector, key_id, signature_overrides) =
            signing_senders_columns(ln, s)?;

        let sender_expr = datastore::parse_mail_addr_expr(sender_expr)
            .map_err(|_| TableFormatError::new(ln, TableFormatErrorKind::InvalidSender))?;
        let domain = datastore::parse_domain_expr(domain)
            .map_err(|_| TableFormatError::new(ln, TableFormatErrorKind::InvalidDomain))?;
        let selector = Selector::new(selector)
            .map_err(|_| TableFormatError::new(ln, TableFormatErrorKind::InvalidSelector))?;

        let signing_config = match signature_overrides {
            Some(f) => {
                let config = read_signing_config_data_source(ln, f)
                    .await
                    .map_err(|e| TableFormatError::new(ln, e))?;
                Some(config)
            }
            None => None,
        };

        entries.push(UnresolvedSigningSender {
            sender_expr,
            domain,
            selector,
            unresolved_key: key_id.into(),
            signing_config,
        });
    }

    Ok(entries)
}

async fn read_signing_config_data_source(
    ln: usize,
    value: &str,
) -> Result<SigningConfigDataSource, TableFormatErrorKind> {
    if let Some(s) = datastore::strip_slurp_prefix(value) {
        let config = read_signing_config_overrides(s)
            .await
            .map_err(TableFormatErrorKind::ReadConfig)?;
        Ok(SigningConfigDataSource::Slurp(Arc::new(config)))
    } else if let Some(s) = datastore::strip_file_prefix(value) {
        Ok(SigningConfigDataSource::File { ln, file: s.into() })
    } else {
        Err(TableFormatErrorKind::InvalidDataSource)
    }
}

async fn find_signing_senders(
    entries: &[UnresolvedSigningSender],
    sender: String,
) -> Result<Vec<UnresolvedSenderMatch>, TableErrorKind> {
    let mut matches = vec![];

    for entry in entries {
        if entry.sender_expr.is_match(&sender) {
            let signing_config = match &entry.signing_config {
                Some(SigningConfigDataSource::Slurp(value)) => Some(value.clone()),
                Some(SigningConfigDataSource::File { ln, file }) => {
                    let o = read_signing_config_overrides(file)
                        .await
                        .map_err(|e| {
                            TableFormatError::new(*ln, TableFormatErrorKind::ReadConfig(e))
                        })?;
                    Some(Arc::new(o))
                }
                None => None,
            };

            matches.push(UnresolvedSenderMatch {
                domain: entry.domain.clone(),
                selector: entry.selector.clone(),
                unresolved_key: entry.unresolved_key.clone(),
                signing_config,
            });
        }
    }

    Ok(matches)
}

async fn scan_signing_senders_table(
    file: &Path,
    sender: String,
) -> Result<Vec<UnresolvedSenderMatch>, TableError> {
    async {
        let file_content = fs::read_to_string(file).await?;
        let matches = scan_signing_senders_table_content(&file_content, sender).await?;
        Ok(matches)
    }
    .await
    .map_err(|e| TableError::new(file, e))
}

async fn scan_signing_senders_table_content(
    file_content: &str,
    sender: String,
) -> Result<Vec<UnresolvedSenderMatch>, TableFormatError> {
    let mut matches = vec![];

    for (ln, s) in format::lines(file_content) {
        let (sender_expr, domain, selector, key_id, signature_overrides) =
            signing_senders_columns(ln, s)?;
        let sender_expr = datastore::parse_mail_addr_expr(sender_expr)
            .map_err(|_| TableFormatError::new(ln, TableFormatErrorKind::InvalidSender))?;

        if sender_expr.is_match(&sender) {
            let domain = datastore::parse_domain_expr(domain)
                .map_err(|_| TableFormatError::new(ln, TableFormatErrorKind::InvalidDomain))?;
            let selector = Selector::new(selector)
                .map_err(|_| TableFormatError::new(ln, TableFormatErrorKind::InvalidSelector))?;

            let signing_config = match signature_overrides {
                Some(f) => {
                    let s = strip_fs_prefix(f).map_err(|e| TableFormatError::new(ln, e))?;

                    let config = read_signing_config_overrides(s)
                        .await
                        .map_err(|e| {
                            TableFormatError::new(ln, TableFormatErrorKind::ReadConfig(e))
                        })?;
                    Some(Arc::new(config))
                }
                None => None,
            };

            matches.push(UnresolvedSenderMatch {
                domain,
                selector,
                unresolved_key: key_id.into(),
                signing_config,
            });
        }
    }

    Ok(matches)
}

fn signing_senders_columns(
    ln: usize,
    line: &str,
) -> Result<(&str, &str, &str, &str, Option<&str>), TableFormatError> {
    let mut cols = line.split_ascii_whitespace();

    match (cols.next(), cols.next(), cols.next(), cols.next(), cols.next()) {
        (Some(c1), Some(c2), Some(c3), Some(c4), c5) => {
            if c5.is_some() && cols.next().is_some() {
                return Err(TableFormatError::new(ln, TableFormatErrorKind::TooManyFields));
            }
            Ok((c1, c2, c3, c4, c5))
        }
        _ => Err(TableFormatError::new(ln, TableFormatErrorKind::InvalidLine)),
    }
}

async fn read_signing_config_overrides(
    file: impl AsRef<Path>,
) -> Result<PartialSigningConfig, ConfigError> {
    let file = file.as_ref();
    async {
        let file_content = fs::read_to_string(file).await?;
        let overrides = format::parse_signing_config_overrides(&file_content).await?;
        Ok(overrides)
    }
    .await
    .map_err(|e| ConfigError {
        file: file.into(),
        kind: e,
    })
}

type SigningKeyDataSource = FsDataSource<Arc<SigningKey>>;

struct SlurpSigningKeysDb {
    file: PathBuf,
    keys: HashMap<String, SigningKeyDataSource>,
}

struct KeysDebug<'a>(&'a HashMap<String, SigningKeyDataSource>);

impl fmt::Debug for KeysDebug<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        struct Omitted;

        impl fmt::Debug for Omitted {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "<omitted>")
            }
        }

        f.debug_map()
            .entries(self.0.keys().map(|k| (k, &Omitted)))
            .finish()
    }
}

impl fmt::Debug for SlurpSigningKeysDb {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlurpSigningKeysDb")
            .field("file", &self.file)
            .field("keys", &KeysDebug(&self.keys))
            .finish()
    }
}

#[derive(Debug)]
struct FileSigningKeysDb {
    file: PathBuf,
}

pub async fn read_slurp_signing_keys(file: &str) -> Result<impl SigningKeysDb, TableError> {
    let keys = read_signing_keys_table(file).await?;
    Ok(SlurpSigningKeysDb { file: file.into(), keys })
}

pub async fn read_file_signing_keys(file: &str) -> Result<impl SigningKeysDb, TableError> {
    let file = file.into();
    Ok(FileSigningKeysDb { file })
}

impl SigningKeysDb for SlurpSigningKeysDb {
    fn check_cached_key_ids(&self, key_ids: Vec<Arc<str>>) -> Result<(), Arc<str>> {
        for k in key_ids {
            if !self.keys.contains_key(k.as_ref()) {
                return Err(k);
            }
        }
        Ok(())
    }

    fn resolve_ids(&self, key_ids: Vec<Arc<str>>) -> BoxFuture<'_, SigningKeysResult> {
        Box::pin(async move {
            let map = resolve_signing_key_ids(&self.keys, key_ids)
                .await
                .map_err(|e| TableError::new(&self.file, e))?;
            Ok(map)
        })
    }
}

impl SigningKeysDb for FileSigningKeysDb {
    fn resolve_ids(&self, key_ids: Vec<Arc<str>>) -> BoxFuture<'_, SigningKeysResult> {
        Box::pin(async move {
            let map = resolve_signing_key_ids_table(&self.file, key_ids).await?;
            Ok(map)
        })
    }
}

async fn read_signing_keys_table(
    file: &str,
) -> Result<HashMap<String, SigningKeyDataSource>, TableError> {
    async {
        let file_content = fs::read_to_string(file).await?;
        let map = parse_signing_keys_table(&file_content).await?;
        Ok(map)
    }
    .await
    .map_err(|e| TableError::new(file, e))
}

async fn parse_signing_keys_table(
    file_content: &str,
) -> Result<HashMap<String, SigningKeyDataSource>, TableFormatError> {
    let mut map = HashMap::new();

    for (ln, s) in format::lines(file_content) {
        let (id, value) = signing_keys_columns(ln, s)?;

        if map.contains_key(id) {
            return Err(TableFormatError::new(ln, TableFormatErrorKind::DuplicateKey));
        }

        let key_ds = read_signing_key_data_source(ln, value)
            .await
            .map_err(|e| TableFormatError::new(ln, e))?;

        map.insert(id.into(), key_ds);
    }

    Ok(map)
}

async fn read_signing_key_data_source(
    ln: usize,
    value: &str,
) -> Result<SigningKeyDataSource, TableFormatErrorKind> {
    if let Some(s) = datastore::strip_slurp_prefix(value) {
        let key = read_signing_key(s)
            .await
            .map_err(|e| TableFormatErrorKind::ReadKeyFile(SigningKeyError::new(s, e)))?;
        Ok(SigningKeyDataSource::Slurp(Arc::new(key)))
    } else if let Some(s) = datastore::strip_file_prefix(value) {
        Ok(SigningKeyDataSource::File { ln, file: s.into() })
    } else {
        Err(TableFormatErrorKind::InvalidDataSource)
    }
}

async fn resolve_signing_key_ids(
    keys: &HashMap<String, SigningKeyDataSource>,
    key_ids: Vec<Arc<str>>,
) -> Result<Vec<Arc<SigningKey>>, TableErrorKind> {
    let mut resolved_keys = vec![];

    for key_id in key_ids {
        let key_ds = keys.get(key_id.as_ref())
            .ok_or(TableErrorKind::MissingKeyId(key_id))?;

        let key = match key_ds {
            SigningKeyDataSource::Slurp(value) => value.clone(),
            SigningKeyDataSource::File { ln, file } => {
                let key = read_signing_key(file)
                    .await
                    .map_err(|e| {
                        TableFormatError::new(*ln, TableFormatErrorKind::ReadKeyFile(SigningKeyError::new(file, e)))
                    })?;
                Arc::new(key)
            }
        };

        resolved_keys.push(key);
    }

    Ok(resolved_keys)
}

async fn resolve_signing_key_ids_table(
    file: &Path,
    key_ids: Vec<Arc<str>>,
) -> Result<Vec<Arc<SigningKey>>, TableError> {
    async {
        let file_content = fs::read_to_string(file).await?;
        let matches = resolve_signing_key_ids_table_content(&file_content, key_ids).await?;
        Ok(matches)
    }
    .await
    .map_err(|e| TableError::new(file, e))
}

async fn resolve_signing_key_ids_table_content(
    file_content: &str,
    key_ids: Vec<Arc<str>>,
) -> Result<Vec<Arc<SigningKey>>, TableErrorKind> {
    let mut map = HashMap::with_capacity(key_ids.len());

    for (ln, s) in format::lines(file_content) {
        let (id, value) = signing_keys_columns(ln, s)?;

        if map.contains_key(id) {
            return Err(TableFormatError::new(ln, TableFormatErrorKind::DuplicateKey).into());
        }

        if key_ids.iter().any(|k| k.as_ref() == id) {
            let s = strip_fs_prefix(value).map_err(|e| TableFormatError::new(ln, e))?;

            let key = read_signing_key(s)
                .await
                .map_err(|e| {
                    TableFormatError::new(ln, TableFormatErrorKind::ReadKeyFile(SigningKeyError::new(s, e)))
                })?;
            map.insert(id, key.into());
        }
    }

    let keys = key_ids.into_iter()
        .map(|k| {
            map.get(k.as_ref())
                .cloned()
                .ok_or(TableErrorKind::MissingKeyId(k))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(keys)
}

fn signing_keys_columns(ln: usize, line: &str) -> Result<(&str, &str), TableFormatError> {
    let mut cols = line.split_ascii_whitespace();

    match (cols.next(), cols.next()) {
        (Some(c1), Some(c2)) => {
            if cols.next().is_some() {
                return Err(TableFormatError::new(ln, TableFormatErrorKind::TooManyFields));
            }
            Ok((c1, c2))
        }
        _ => Err(TableFormatError::new(ln, TableFormatErrorKind::InvalidLine)),
    }
}

async fn read_signing_key(file: impl AsRef<Path>) -> io::Result<SigningKey> {
    let file_content = fs::read_to_string(file.as_ref()).await?;

    let key = SigningKey::from_pkcs8_pem(&file_content)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

    Ok(key)
}

type ConfigOverridesDataSource = FsDataSource<Arc<ConfigOverrides>>;

#[derive(Debug)]
struct NetworkOverride {
    net: IpNet,
    config: ConfigOverridesDataSource,
}

#[derive(Debug)]
struct SlurpConnectionOverridesDb {
    file: PathBuf,
    entries: Vec<NetworkOverride>,
}

#[derive(Debug)]
struct FileConnectionOverridesDb {
    file: PathBuf,
}

pub async fn read_slurp_connection_overrides(
    file: &str,
) -> Result<impl ConnectionOverridesDb, TableError> {
    let entries = read_connection_overrides_table(file).await?;
    Ok(SlurpConnectionOverridesDb { file: file.into(), entries })
}

pub async fn read_file_connection_overrides(
    file: &str,
) -> Result<impl ConnectionOverridesDb, TableError> {
    let file = file.into();
    Ok(FileConnectionOverridesDb { file })
}

impl ConnectionOverridesDb for SlurpConnectionOverridesDb {
    fn find_all(&self, ip: IpAddr) -> BoxFuture<'_, ConfigOverridesResult> {
        Box::pin(async move {
            let matches = find_connection_overrides(&self.entries, ip)
                .await
                .map_err(|e| TableError::new(&self.file, e))?;
            Ok(matches)
        })
    }
}

impl ConnectionOverridesDb for FileConnectionOverridesDb {
    fn find_all(&self, ip: IpAddr) -> BoxFuture<'_, ConfigOverridesResult> {
        Box::pin(async move {
            let matches = scan_connection_overrides_table(&self.file, ip).await?;
            Ok(matches)
        })
    }
}

async fn read_connection_overrides_table(file: &str) -> Result<Vec<NetworkOverride>, TableError> {
    async {
        let file_content = fs::read_to_string(file).await?;
        let overrides = parse_connection_overrides_table(&file_content).await?;
        Ok(overrides)
    }
    .await
    .map_err(|e| TableError::new(file, e))
}

async fn parse_connection_overrides_table(
    file_content: &str,
) -> Result<Vec<NetworkOverride>, TableFormatError> {
    let mut entries = vec![];

    for (ln, s) in format::lines(file_content) {
        let (network_expr, overrides) = config_overrides_columns(ln, s)?;

        let net = datastore::parse_network_expr(network_expr)
            .map_err(|_| TableFormatError::new(ln, TableFormatErrorKind::InvalidNetwork))?;

        let config = read_config_overrides_data_source(ln, overrides)
            .await
            .map_err(|e| TableFormatError::new(ln, e))?;

        entries.push(NetworkOverride { net, config });
    }

    Ok(entries)
}

async fn find_connection_overrides(
    entries: &[NetworkOverride],
    ip: IpAddr,
) -> Result<Vec<Arc<ConfigOverrides>>, TableErrorKind> {
    let mut matches = vec![];

    for entry in entries {
        if entry.net.contains(&ip) {
            let overrides = get_config_overrides(&entry.config).await?;
            matches.push(overrides);
        }
    }

    Ok(matches)
}

async fn scan_connection_overrides_table(
    file: &Path,
    ip: IpAddr,
) -> Result<Vec<Arc<ConfigOverrides>>, TableError> {
    async {
        let file_content = fs::read_to_string(file).await?;
        let matches = scan_connection_overrides_table_content(&file_content, ip).await?;
        Ok(matches)
    }
    .await
    .map_err(|e| TableError::new(file, e))
}

async fn scan_connection_overrides_table_content(
    file_content: &str,
    ip: IpAddr,
) -> Result<Vec<Arc<ConfigOverrides>>, TableFormatError> {
    let mut matches = vec![];

    for (ln, s) in format::lines(file_content) {
        let (network_expr, overrides) = config_overrides_columns(ln, s)?;

        let net = datastore::parse_network_expr(network_expr)
            .map_err(|_| TableFormatError::new(ln, TableFormatErrorKind::InvalidNetwork))?;

        if net.contains(&ip) {
            let overrides = strip_fs_prefix(overrides).map_err(|e| TableFormatError::new(ln, e))?;
            let overrides = read_config_overrides(overrides)
                .await
                .map_err(|e| {
                    TableFormatError::new(ln, TableFormatErrorKind::ReadConfig(e))
                })?;

            matches.push(Arc::new(overrides));
        }
    }

    Ok(matches)
}

#[derive(Debug)]
struct MailAddrOverride {
    expr: Regex,
    config: ConfigOverridesDataSource,
}

#[derive(Debug)]
struct SlurpRecipientOverridesDb {
    file: PathBuf,
    entries: Vec<MailAddrOverride>,
}

#[derive(Debug)]
struct FileRecipientOverridesDb {
    file: PathBuf,
}

pub async fn read_slurp_recipient_overrides(
    file: &str,
) -> Result<impl RecipientOverridesDb, TableError> {
    let entries = read_recipient_overrides_table(file).await?;
    Ok(SlurpRecipientOverridesDb { file: file.into(), entries })
}

pub async fn read_file_recipient_overrides(
    file: &str,
) -> Result<impl RecipientOverridesDb, TableError> {
    let file = file.into();
    Ok(FileRecipientOverridesDb { file })
}

impl RecipientOverridesDb for SlurpRecipientOverridesDb {
    fn find_all(&self, recipients: Vec<String>) -> BoxFuture<'_, ConfigOverridesResult> {
        Box::pin(async move {
            let matches = find_recipient_overrides(&self.entries, recipients)
                .await
                .map_err(|e| TableError::new(&self.file, e))?;
            Ok(matches)
        })
    }
}

impl RecipientOverridesDb for FileRecipientOverridesDb {
    fn find_all(&self, recipients: Vec<String>) -> BoxFuture<'_, ConfigOverridesResult> {
        Box::pin(async move {
            let matches = scan_recipient_overrides_table(&self.file, recipients).await?;
            Ok(matches)
        })
    }
}

async fn read_recipient_overrides_table(file: &str) -> Result<Vec<MailAddrOverride>, TableError> {
    async {
        let file_content = fs::read_to_string(file).await?;
        let overrides = parse_recipient_overrides_table(&file_content).await?;
        Ok(overrides)
    }
    .await
    .map_err(|e| TableError::new(file, e))
}

async fn parse_recipient_overrides_table(
    file_content: &str,
) -> Result<Vec<MailAddrOverride>, TableFormatError> {
    let mut entries = vec![];

    for (ln, s) in format::lines(file_content) {
        let (sender_expr, overrides) = config_overrides_columns(ln, s)?;

        let expr = datastore::parse_mail_addr_expr(sender_expr)
            .map_err(|_| TableFormatError::new(ln, TableFormatErrorKind::InvalidRecipient))?;

        let config = read_config_overrides_data_source(ln, overrides)
            .await
            .map_err(|e| TableFormatError::new(ln, e))?;

        entries.push(MailAddrOverride { expr, config });
    }

    Ok(entries)
}

async fn find_recipient_overrides(
    entries: &[MailAddrOverride],
    recipients: Vec<String>,
) -> Result<Vec<Arc<ConfigOverrides>>, TableErrorKind> {
    let mut recipients_ascii: Vec<Option<Result<String, ()>>> =
        Vec::with_capacity(recipients.len());

    let mut matches = vec![];

    for entry in entries {
        for (recipient, recipient_ascii) in recipients.iter().zip(recipients_ascii.iter_mut()) {
            let recipient_ascii_domain = datastore::get_recipient_ascii_domain(recipient, recipient_ascii);

            // Does the expr match the recipient string directly?
            // Or does it match the recipient with normalised domain?
            if entry.expr.is_match(recipient)
                || matches!(recipient_ascii_domain, Ok(r) if entry.expr.is_match(r))
            {
                let overrides = get_config_overrides(&entry.config).await?;
                matches.push(overrides);
                break;
            }
        }
    }

    Ok(matches)
}

async fn scan_recipient_overrides_table(
    file: &Path,
    recipients: Vec<String>,
) -> Result<Vec<Arc<ConfigOverrides>>, TableError> {
    async {
        let file_content = fs::read_to_string(file).await?;
        let matches = scan_recipient_overrides_table_content(&file_content, recipients).await?;
        Ok(matches)
    }
    .await
    .map_err(|e| TableError::new(file, e))
}

async fn scan_recipient_overrides_table_content(
    file_content: &str,
    recipients: Vec<String>,
) -> Result<Vec<Arc<ConfigOverrides>>, TableFormatError> {
    let mut recipients_ascii: Vec<Option<Result<String, ()>>> =
        Vec::with_capacity(recipients.len());

    let mut matches = vec![];

    for (ln, s) in format::lines(file_content) {
        let (sender_expr, overrides) = config_overrides_columns(ln, s)?;

        let expr = datastore::parse_mail_addr_expr(sender_expr)
            .map_err(|_| TableFormatError::new(ln, TableFormatErrorKind::InvalidRecipient))?;

        for (recipient, recipient_ascii) in recipients.iter().zip(recipients_ascii.iter_mut()) {
            let recipient_ascii_domain =
                datastore::get_recipient_ascii_domain(recipient, recipient_ascii);

            if expr.is_match(recipient)
                || matches!(recipient_ascii_domain, Ok(r) if expr.is_match(r))
            {
                let overrides = strip_fs_prefix(overrides).map_err(|e| TableFormatError::new(ln, e))?;
                let overrides = read_config_overrides(overrides)
                    .await
                    .map_err(|e| {
                        TableFormatError::new(ln, TableFormatErrorKind::ReadConfig(e))
                    })?;

                matches.push(Arc::new(overrides));
                break;
            }
        }
    }

    Ok(matches)
}

async fn read_config_overrides_data_source(
    ln: usize,
    value: &str,
) -> Result<ConfigOverridesDataSource, TableFormatErrorKind> {
    if let Some(s) = datastore::strip_slurp_prefix(value) {
        let overrides = read_config_overrides(s)
            .await
            .map_err(TableFormatErrorKind::ReadConfig)?;
        Ok(ConfigOverridesDataSource::Slurp(Arc::new(overrides)))
    } else if let Some(s) = datastore::strip_file_prefix(value) {
        Ok(ConfigOverridesDataSource::File { ln, file: s.into() })
    } else {
        Err(TableFormatErrorKind::InvalidDataSource)
    }
}

fn config_overrides_columns(ln: usize, line: &str) -> Result<(&str, &str), TableFormatError> {
    let mut cols = line.split_ascii_whitespace();

    match (cols.next(), cols.next()) {
        (Some(c1), Some(c2)) => {
            if cols.next().is_some() {
                return Err(TableFormatError::new(ln, TableFormatErrorKind::TooManyFields));
            }
            Ok((c1, c2))
        }
        _ => Err(TableFormatError::new(ln, TableFormatErrorKind::InvalidLine)),
    }
}

async fn get_config_overrides(
    ds: &ConfigOverridesDataSource,
) -> Result<Arc<ConfigOverrides>, TableFormatError> {
    match ds {
        ConfigOverridesDataSource::Slurp(value) => Ok(value.clone()),
        ConfigOverridesDataSource::File { ln, file } => {
            let o = read_config_overrides(file)
                .await
                .map_err(|e| {
                    TableFormatError::new(*ln, TableFormatErrorKind::ReadConfig(e))
                })?;
            Ok(Arc::new(o))
        }
    }
}

async fn read_config_overrides(file: impl AsRef<Path>) -> Result<ConfigOverrides, ConfigError> {
    let file = file.as_ref();
    async {
        let file_content = fs::read_to_string(file).await?;
        let overrides = format::parse_config_overrides(&file_content).await?;
        Ok(overrides)
    }
    .await
    .map_err(|e| ConfigError {
        file: file.into(),
        kind: e,
    })
}

fn strip_fs_prefix(s: &str) -> Result<&str, TableFormatErrorKind> {
    datastore::strip_slurp_prefix(s)
        .or_else(|| datastore::strip_file_prefix(s))
        .ok_or(TableFormatErrorKind::InvalidDataSource)
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use viadkim::signature::DomainName;

    #[tokio::test]
    async fn slurp_signing_senders_find_all() {
        let domain = DomainExpr::Domain(DomainName::new("example.com").unwrap());
        let selector = Selector::new("sel1").unwrap();

        let signing_senders = SlurpSigningSendersDb {
            file: "unused".into(),
            entries: vec![UnresolvedSigningSender {
                sender_expr: Regex::new(".*@mail.example.com").unwrap(),
                domain: domain.clone(),
                selector: selector.clone(),
                unresolved_key: "key1".into(),
                signing_config: None,
            }],
        };

        let matches = signing_senders.find_all("itsame@mail.example.com".into())
            .await
            .unwrap();

        assert_eq!(matches.len(), 1);

        let match_ = matches.into_iter().next().unwrap();

        assert_eq!(match_.selector, selector);
    }
}
