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
        format::{self, ParseConfigError},
        model::ConfigOverrides,
    },
    datastore::{
        self, ConfigOverridesResult, ConnectionOverridesDb, RecipientOverridesDb, SigningKeysDb,
        SigningKeysResult, SigningSendersDb, SigningSendersResult, UnresolvedSenderMatch,
    },
    util::BoxFuture,
};
use futures_util::stream::TryStreamExt;
use log::warn;
use sqlx::{
    sqlite::SqliteConnectOptions, ConnectOptions, Connection, QueryBuilder, Row, SqliteConnection,
};
use std::{
    collections::HashMap,
    error::Error,
    fmt::{self, Display, Formatter},
    net::IpAddr,
    str::FromStr,
    sync::Arc,
};
use viadkim::{
    crypto::{DecodeSigningKeyError, SigningKey},
    signature::Selector,
};

#[derive(Debug)]
pub struct SqlError {
    pub conn_url: String,
    pub kind: SqlErrorKind,
}

impl SqlError {
    pub fn new(conn_url: impl Into<String>, kind: SqlErrorKind) -> Self {
        Self {
            conn_url: conn_url.into(),
            kind,
        }
    }
}

impl Display for SqlError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SqlErrorKind::TableNameSyntax => write!(f, "wrong table name syntax in \"{}\"", self.conn_url),
            SqlErrorKind::Lib(_) => write!(f, "SQL library error for URL {}", self.conn_url),
            SqlErrorKind::Format(_) => write!(f, "wrong data format in database at URL {}", self.conn_url),
            SqlErrorKind::MissingKeyId(key_id) => {
                write!(f, "key ID \"{key_id}\" not found in database at URL {}", self.conn_url)
            }
        }
    }
}

impl Error for SqlError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            SqlErrorKind::TableNameSyntax | SqlErrorKind::MissingKeyId(_) => None,
            SqlErrorKind::Lib(e) => Some(e),
            SqlErrorKind::Format(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub enum SqlErrorKind {
    TableNameSyntax,
    Lib(sqlx::Error),
    Format(DataFormatError),
    MissingKeyId(Arc<str>),
}

impl Display for SqlErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TableNameSyntax => write!(f, "wrong table name syntax"),
            Self::Lib(_) => write!(f, "SQL library error"),
            Self::Format(_) => write!(f, "wrong data format in database"),
            Self::MissingKeyId(key_id) => write!(f, "key ID \"{key_id}\" not found in database"),
        }
    }
}

impl From<sqlx::Error> for SqlErrorKind {
    fn from(error: sqlx::Error) -> Self {
        Self::Lib(error)
    }
}

impl From<DataFormatError> for SqlErrorKind {
    fn from(error: DataFormatError) -> Self {
        Self::Format(error)
    }
}

#[derive(Debug)]
pub enum DataFormatError {
    InvalidSender,
    InvalidDomain,
    InvalidSelector,
    InvalidNetwork,
    InvalidRecipient,
    ParseConfig(ParseConfigError),
    ParseSigningKey(DecodeSigningKeyError),
}

impl Display for DataFormatError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSender => write!(f, "invalid sender expression"),
            Self::InvalidDomain => write!(f, "invalid domain expression"),
            Self::InvalidSelector => write!(f, "invalid selector"),
            Self::InvalidNetwork => write!(f, "invalid network address"),
            Self::InvalidRecipient => write!(f, "invalid recipient expression"),
            Self::ParseConfig(_) => write!(f, "invalid included configuration"),
            Self::ParseSigningKey(_) => write!(f, "invalid included signing key"),
        }
    }
}

impl Error for DataFormatError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidSender
            | Self::InvalidDomain
            | Self::InvalidSelector
            | Self::InvalidNetwork
            | Self::InvalidRecipient => None,
            Self::ParseConfig(e) => Some(e),
            Self::ParseSigningKey(e) => Some(e),
        }
    }
}

#[derive(Debug)]
struct SqliteSigningSendersDb {
    url: String,
    table_name: Option<String>,
}

pub async fn read_signing_senders(conn_url: &str) -> Result<impl SigningSendersDb, SqlError> {
    let (url, table_name) = parse_conn_url(conn_url)?;
    Ok(SqliteSigningSendersDb { url, table_name })
}

impl SigningSendersDb for SqliteSigningSendersDb {
    fn find_all(&self, sender: String) -> BoxFuture<'_, SigningSendersResult> {
        Box::pin(async move {
            let matches =
                find_signing_senders(&self.url, self.table_name.as_deref(), sender).await?;
            Ok(matches)
        })
    }
}

async fn find_signing_senders(
    url: &str,
    table_name: Option<&str>,
    sender: String,
) -> Result<Vec<UnresolvedSenderMatch>, SqlError> {
    let mut conn = connect(url)
        .await
        .map_err(|e| SqlError::new(url, SqlErrorKind::Lib(e)))?;

    let result = find_signing_senders_conn(&mut conn, table_name, sender)
        .await
        .map_err(|e| SqlError::new(url, e));

    close_or_warn(conn).await;

    result
}

async fn find_signing_senders_conn(
    conn: &mut SqliteConnection,
    table_name: Option<&str>,
    sender: String,
) -> Result<Vec<UnresolvedSenderMatch>, SqlErrorKind> {
    let table_name = table_name.unwrap_or("signing_senders");
    let q = format!("SELECT sender, domain, selector, signature_overrides, signing_key FROM {table_name}");

    let mut rows = sqlx::query(&q).fetch(conn);

    let mut matches = vec![];

    while let Some(row) = rows.try_next().await? {
        let sender_expr: &str = row.try_get("sender")?;
        let domain: &str = row.try_get("domain")?;
        let selector: &str = row.try_get("selector")?;
        let signature_overrides: Option<&str> = row.try_get("signature_overrides")?;
        let signing_key: &str = row.try_get("signing_key")?;

        let sender_expr = datastore::parse_mail_addr_expr(sender_expr)
            .map_err(|_| DataFormatError::InvalidSender)?;

        if sender_expr.is_match(&sender) {
            let domain = datastore::parse_domain_expr(domain)
                .map_err(|_| DataFormatError::InvalidDomain)?;
            let selector = Selector::new(selector)
                .map_err(|_| DataFormatError::InvalidSelector)?;

            let signing_config = match signature_overrides {
                Some(o) => {
                    let config = format::parse_signing_config_overrides(o)
                        .await
                        .map_err(DataFormatError::ParseConfig)?;
                    Some(Arc::new(config))
                }
                None => None,
            };

            matches.push(UnresolvedSenderMatch {
                domain,
                selector,
                unresolved_key: signing_key.into(),
                signing_config,
            });
        }
    }

    Ok(matches)
}

#[derive(Debug)]
struct SqliteSigningKeysDb {
    url: String,
    table_name: Option<String>,
}

pub async fn read_signing_keys(conn_url: &str) -> Result<impl SigningKeysDb, SqlError> {
    let (url, table_name) = parse_conn_url(conn_url)?;
    Ok(SqliteSigningKeysDb { url, table_name })
}

impl SigningKeysDb for SqliteSigningKeysDb {
    fn resolve_ids(&self, key_ids: Vec<Arc<str>>) -> BoxFuture<'_, SigningKeysResult> {
        Box::pin(async move {
            let matches = find_signing_keys(&self.url, self.table_name.as_deref(), key_ids)
                .await
                .map_err(|e| SqlError::new(&self.url, e))?;
            Ok(matches)
        })
    }
}

async fn find_signing_keys(
    url: &str,
    table_name: Option<&str>,
    key_ids: Vec<Arc<str>>,
) -> Result<Vec<Arc<SigningKey>>, SqlErrorKind> {
    // Important to shortcut as an empty input leads to invalid SQL below.
    if key_ids.is_empty() {
        return Ok(vec![]);
    }

    let mut conn = connect(url).await?;

    let result = find_signing_keys_conn(&mut conn, table_name, &key_ids).await;

    close_or_warn(conn).await;

    let map = result?;

    let keys = key_ids.into_iter()
        .map(|k| {
            map.get(k.as_ref())
                .cloned()
                .ok_or(SqlErrorKind::MissingKeyId(k))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(keys)
}

async fn find_signing_keys_conn(
    conn: &mut SqliteConnection,
    table_name: Option<&str>,
    key_ids: &[Arc<str>],
) -> Result<HashMap<String, Arc<SigningKey>>, SqlErrorKind> {
    let table_name = table_name.unwrap_or("signing_keys");

    let mut query = QueryBuilder::new(format!(
        "SELECT key_id, key_pem FROM {table_name} WHERE key_id IN ("
    ));

    let mut qargs = query.separated(", ");
    for key_id in key_ids {
        qargs.push_bind(key_id.as_ref());
    }
    qargs.push_unseparated(")");

    let q = query.build();

    let mut map = HashMap::with_capacity(key_ids.len());

    let mut rows = q.fetch(conn);

    while let Some(row) = rows.try_next().await? {
        let key_id: &str = row.try_get("key_id")?;
        let key_pem: &str = row.try_get("key_pem")?;

        let key = SigningKey::from_pkcs8_pem(key_pem).map_err(DataFormatError::ParseSigningKey)?;

        map.insert(key_id.into(), key.into());
    }

    Ok(map)
}

#[derive(Debug)]
struct SqliteConnectionOverridesDb {
    url: String,
    table_name: Option<String>,
}

pub async fn read_connection_overrides(
    conn_url: &str,
) -> Result<impl ConnectionOverridesDb, SqlError> {
    let (url, table_name) = parse_conn_url(conn_url)?;
    Ok(SqliteConnectionOverridesDb { url, table_name })
}

impl ConnectionOverridesDb for SqliteConnectionOverridesDb {
    fn find_all(&self, ip: IpAddr) -> BoxFuture<'_, ConfigOverridesResult> {
        Box::pin(async move {
            Ok(find_connection_overrides(&self.url, self.table_name.as_deref(), ip).await?)
        })
    }
}

async fn find_connection_overrides(
    url: &str,
    table_name: Option<&str>,
    ip: IpAddr,
) -> Result<Vec<Arc<ConfigOverrides>>, SqlError> {
    let mut conn = connect(url)
        .await
        .map_err(|e| SqlError::new(url, SqlErrorKind::Lib(e)))?;

    let result = find_connection_overrides_conn(&mut conn, table_name, ip)
        .await
        .map_err(|e| SqlError::new(url, e));

    close_or_warn(conn).await;

    result
}

async fn find_connection_overrides_conn(
    conn: &mut SqliteConnection,
    table_name: Option<&str>,
    ip: IpAddr,
) -> Result<Vec<Arc<ConfigOverrides>>, SqlErrorKind> {
    let table_name = table_name.unwrap_or("connection_overrides");
    let q = format!("SELECT network, config FROM {table_name}");

    let mut rows = sqlx::query(&q).fetch(conn);

    let mut matches = vec![];

    while let Some(row) = rows.try_next().await? {
        let network: &str = row.try_get("network")?;
        let config: &str = row.try_get("config")?;

        let net = datastore::parse_network_expr(network)
            .map_err(|_| DataFormatError::InvalidNetwork)?;

        if net.contains(&ip) {
            let overrides = format::parse_config_overrides(config)
                .await
                .map_err(DataFormatError::ParseConfig)?;

            matches.push(Arc::new(overrides));
        }
    }

    Ok(matches)
}

#[derive(Debug)]
struct SqliteRecipientOverridesDb {
    url: String,
    table_name: Option<String>,
}

pub async fn read_recipient_overrides(
    conn_url: &str,
) -> Result<impl RecipientOverridesDb, SqlError> {
    let (url, table_name) = parse_conn_url(conn_url)?;
    Ok(SqliteRecipientOverridesDb { url, table_name })
}

impl RecipientOverridesDb for SqliteRecipientOverridesDb {
    fn find_all(&self, recipients: Vec<String>) -> BoxFuture<'_, ConfigOverridesResult> {
        Box::pin(async move {
            Ok(find_recipient_overrides(&self.url, self.table_name.as_deref(), recipients).await?)
        })
    }
}

async fn find_recipient_overrides(
    url: &str,
    table_name: Option<&str>,
    recipients: Vec<String>,
) -> Result<Vec<Arc<ConfigOverrides>>, SqlError> {
    let mut conn = connect(url)
        .await
        .map_err(|e| SqlError::new(url, SqlErrorKind::Lib(e)))?;

    let result = find_recipient_overrides_conn(&mut conn, table_name, recipients)
        .await
        .map_err(|e| SqlError::new(url, e));

    close_or_warn(conn).await;

    result
}

async fn find_recipient_overrides_conn(
    conn: &mut SqliteConnection,
    table_name: Option<&str>,
    recipients: Vec<String>,
) -> Result<Vec<Arc<ConfigOverrides>>, SqlErrorKind> {
    let table_name = table_name.unwrap_or("recipient_overrides");
    let q = format!("SELECT recipient, config FROM {table_name}");

    let mut rows = sqlx::query(&q).fetch(conn);

    let mut recipients_ascii: Vec<Option<Result<String, ()>>> =
        Vec::with_capacity(recipients.len());

    let mut matches = vec![];

    while let Some(row) = rows.try_next().await? {
        let recipient: &str = row.try_get("recipient")?;
        let config: &str = row.try_get("config")?;

        let expr = datastore::parse_mail_addr_expr(recipient)
            .map_err(|_| DataFormatError::InvalidRecipient)?;

        for (recipient, recipient_ascii) in recipients.iter().zip(recipients_ascii.iter_mut()) {
            let recipient_ascii_domain =
                datastore::get_recipient_ascii_domain(recipient, recipient_ascii);

            if expr.is_match(recipient)
                || matches!(recipient_ascii_domain, Ok(r) if expr.is_match(r))
            {
                let overrides = format::parse_config_overrides(config)
                    .await
                    .map_err(DataFormatError::ParseConfig)?;
                matches.push(Arc::new(overrides));
                break;
            }
        }
    }

    Ok(matches)
}

fn parse_conn_url(conn_url: &str) -> Result<(String, Option<String>), SqlError> {
    if let Some((url, table_name)) = conn_url.rsplit_once('#') {
        if table_name.is_empty() {
            Ok((url.into(), None))
        } else if table_name.starts_with(|c: char| c.is_alphabetic() || c == '_')
            && table_name.chars().all(|c| c.is_alphanumeric() || c == '_')
        {
            Ok((url.into(), Some(table_name.into())))
        } else {
            Err(SqlError::new(conn_url, SqlErrorKind::TableNameSyntax))
        }
    } else {
        Ok((conn_url.into(), None))
    }
}

async fn connect(conn_url: &str) -> sqlx::Result<SqliteConnection> {
    SqliteConnectOptions::from_str(conn_url)?
        .disable_statement_logging()
        .connect()
        .await
}

async fn close_or_warn(conn: SqliteConnection) {
    if let Err(e) = conn.close().await {
        warn!("failed to cleanly drop SQLite database connection: {e}");
    }
}
