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

use crate::config::{
    format,
    model::{
        ConnectionOverrides, DomainExpr, IdentityDomainExpr, IdentityExpr, LocalPartExpr,
        MailAddrOverride, NetworkOverride, PartialSigningConfig, RecipientOverrides,
    },
    ConfigError,
};
use ipnet::IpNet;
use regex::Regex;
use std::{
    collections::HashMap,
    error::Error,
    fmt::{self, Display, Formatter},
    io::{self, ErrorKind},
    net::{AddrParseError, IpAddr},
    path::PathBuf,
    str::FromStr,
};
use tokio::fs;
use viadkim::{
    crypto::SigningKey,
    signature::{DomainName, ParseDomainError, Selector},
};

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

impl Error for SigningKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.kind)
    }
}

impl Display for SigningKeyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to read signing key from {}", self.file.display())
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
            | DuplicateKey
            | InvalidSender
            | InvalidDomain
            | InvalidSelector
            | InvalidNetwork
            | InvalidRecipient
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
            | DuplicateKey
            | InvalidSender
            | InvalidDomain
            | InvalidSelector
            | InvalidNetwork
            | InvalidRecipient
            | InvalidFileSyntax => write!(f, ": {}", self.kind),
            ReadKeyFile(_) | ReadConfig(_) => Ok(()),
        }
    }
}

#[derive(Debug)]
pub enum TableFormatErrorKind {
    InvalidLine,
    TooManyFields,
    DuplicateKey,
    InvalidSender,
    InvalidDomain,
    InvalidSelector,
    InvalidNetwork,
    InvalidRecipient,
    InvalidFileSyntax,
    ReadKeyFile(SigningKeyError),
    ReadConfig(Box<ConfigError>),  // recursive, but never more than one level
}

impl Display for TableFormatErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLine => write!(f, "invalid line syntax"),
            Self::TooManyFields => write!(f, "too many fields in line"),
            Self::DuplicateKey => write!(f, "duplicate key in table with unique keys"),
            Self::InvalidSender => write!(f, "invalid sender expression"),
            Self::InvalidDomain => write!(f, "invalid domain expression"),
            Self::InvalidSelector => write!(f, "invalid selector"),
            Self::InvalidNetwork => write!(f, "invalid network address"),
            Self::InvalidRecipient => write!(f, "invalid recipient expression"),
            Self::InvalidFileSyntax => write!(f, "invalid included file syntax"),
            Self::ReadKeyFile(_) => write!(f, "invalid included key file"),
            Self::ReadConfig(_) => write!(f, "invalid included configuration"),
        }
    }
}

#[derive(Debug)]
pub struct RawSigningSender {
    pub sender_expr: Regex,
    pub domain_expr: DomainExpr,
    pub selector: Selector,
    pub key_name: String,
    pub signing_config: Option<PartialSigningConfig>,
}

pub async fn read_signing_keys_table(
    file_name: &str,
) -> Result<HashMap<String, SigningKey>, TableError> {
    async {
        let file_content = fs::read_to_string(file_name).await?;

        let map = parse_signing_keys_table(&file_content).await?;

        Ok(map)
    }
    .await
    .map_err(|e| TableError::new(file_name, e))
}

pub async fn read_signing_senders_table(
    file_name: &str,
) -> Result<Vec<RawSigningSender>, TableError> {
    async {
        let file_content = fs::read_to_string(file_name).await?;

        let map = parse_signing_senders_table(&file_content).await?;

        Ok(map)
    }
    .await
    .map_err(|e| TableError::new(file_name, e))
}

pub async fn read_connection_overrides_table(
    file_name: &str,
) -> Result<ConnectionOverrides, TableError> {
    async {
        let file_content = fs::read_to_string(file_name).await?;

        let overrides = parse_connection_overrides_table(&file_content).await?;

        Ok(overrides)
    }
    .await
    .map_err(|e| TableError::new(file_name, e))
}

pub async fn read_recipient_overrides_table(
    file_name: &str,
) -> Result<RecipientOverrides, TableError> {
    async {
        let file_content = fs::read_to_string(file_name).await?;

        let overrides = parse_recipient_overrides_table(&file_content).await?;

        Ok(overrides)
    }
    .await
    .map_err(|e| TableError::new(file_name, e))
}

async fn parse_signing_keys_table(
    file_content: &str,
) -> Result<HashMap<String, SigningKey>, TableFormatError> {
    let mut map = HashMap::new();

    for (num, line) in format::lines(file_content) {
        let mut iter = line.split_ascii_whitespace();

        let (name, value) = match (iter.next(), iter.next(), iter.next()) {
            (Some(name), Some(value), None) => (name, value),
            _ => return Err(TableFormatError::new(num, TableFormatErrorKind::InvalidLine)),
        };

        if map.contains_key(name) {
            return Err(TableFormatError::new(num, TableFormatErrorKind::DuplicateKey));
        }

        let file_name = value.strip_prefix('<')
            .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidFileSyntax))?;

        let key = read_signing_key(file_name).await.map_err(|e| {
            let e = SigningKeyError::new(file_name, e);
            TableFormatError::new(num, TableFormatErrorKind::ReadKeyFile(e))
        })?;

        map.insert(name.into(), key);
    }

    Ok(map)
}

async fn read_signing_key(file_name: &str) -> io::Result<SigningKey> {
    let key_file_content = fs::read_to_string(file_name).await?;

    let key = SigningKey::from_pkcs8_pem(&key_file_content)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

    Ok(key)
}

async fn parse_signing_senders_table(
    file_content: &str,
) -> Result<Vec<RawSigningSender>, TableFormatError> {
    let mut entries = vec![];

    for (num, line) in format::lines(file_content) {
        let mut iter = line.split_ascii_whitespace();

        let first_five_cols = (iter.next(), iter.next(), iter.next(), iter.next(), iter.next());
        let (sender_expr, domain_expr, selector, key_name, sig_config_file) = match first_five_cols {
            (Some(s), Some(d), Some(sel), Some(k), config) => (s, d, sel, k, config),
            _ => return Err(TableFormatError::new(num, TableFormatErrorKind::InvalidLine)),
        };

        if sig_config_file.is_some() && iter.next().is_some() {
            return Err(TableFormatError::new(num, TableFormatErrorKind::TooManyFields));
        }

        let sender_expr = parse_mail_addr_expr(sender_expr)
            .map_err(|_| TableFormatError::new(num, TableFormatErrorKind::InvalidSender))?;
        let domain_expr = parse_domain_expr(domain_expr)
            .map_err(|_| TableFormatError::new(num, TableFormatErrorKind::InvalidDomain))?;
        let selector = Selector::new(selector)
            .map_err(|_| TableFormatError::new(num, TableFormatErrorKind::InvalidSelector))?;

        let signing_config = match sig_config_file {
            Some(f) => {
                let file_name = f.strip_prefix('<')
                    .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidFileSyntax))?;

                let config = format::read_signing_config_overrides(file_name)
                    .await
                    .map_err(|e| {
                        TableFormatError::new(num, TableFormatErrorKind::ReadConfig(Box::new(e)))
                    })?;

                Some(config)
            }
            None => None,
        };

        let entry = RawSigningSender {
            sender_expr,
            domain_expr,
            selector,
            key_name: key_name.into(),
            signing_config,
        };

        entries.push(entry);
    }

    Ok(entries)
}

fn parse_domain_expr(s: &str) -> Result<DomainExpr, ParseDomainError> {
    if s == "." {
        return Ok(DomainExpr::SenderDomain);
    }

    if let Some((lhs, rhs)) = s.rsplit_once('@') {
        let domain_part = if rhs == "." {
            IdentityDomainExpr::SenderDomain
        } else {
            match rhs.rsplit_once("..") {
                Some((subdomain, domain)) => {
                    let d_domain = DomainName::new(domain)?;
                    let i_domain = DomainName::new(format!("{subdomain}.{domain}"))?;
                    IdentityDomainExpr::SplitDomain { d_domain, i_domain }
                }
                None => {
                    let domain = DomainName::new(rhs)?;
                    IdentityDomainExpr::Domain(domain)
                }
            }
        };

        let local_part = if lhs.is_empty() {
            None
        } else if lhs == "." {
            Some(LocalPartExpr::SenderLocalPart)
        } else {
            Some(LocalPartExpr::LocalPart(lhs.into()))
        };

        let iexpr = IdentityExpr {
            local_part,
            domain_part,
        };

        return Ok(DomainExpr::Identity(iexpr));
    }

    let domain = DomainName::new(s)?;
    Ok(DomainExpr::Domain(domain))
}

async fn parse_connection_overrides_table(
    file_content: &str,
) -> Result<ConnectionOverrides, TableFormatError> {
    let mut entries = vec![];

    for (num, line) in format::lines(file_content) {
        let mut iter = line.split_ascii_whitespace();

        let (network_expr, overrides_file) = match (iter.next(), iter.next(), iter.next()) {
            (Some(n), Some(o), None) => (n, o),
            _ => return Err(TableFormatError::new(num, TableFormatErrorKind::InvalidLine)),
        };

        let net = parse_network_expr(network_expr)
            .map_err(|_| TableFormatError::new(num, TableFormatErrorKind::InvalidNetwork))?;

        let file_name = overrides_file.strip_prefix('<')
            .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidFileSyntax))?;

        let config = format::read_config_overrides(file_name)
            .await
            .map_err(|e| {
                TableFormatError::new(num, TableFormatErrorKind::ReadConfig(Box::new(e)))
            })?;

        let entry = NetworkOverride { net, config };

        entries.push(entry);
    }

    Ok(ConnectionOverrides { entries })
}

fn parse_network_expr(s: &str) -> Result<IpNet, AddrParseError> {
    IpNet::from_str(s).or_else(|_| IpAddr::from_str(s).map(Into::into))
}

async fn parse_recipient_overrides_table(
    file_content: &str,
) -> Result<RecipientOverrides, TableFormatError> {
    let mut entries = vec![];

    for (num, line) in format::lines(file_content) {
        let mut iter = line.split_ascii_whitespace();

        let (sender_expr, overrides_file) = match (iter.next(), iter.next(), iter.next()) {
            (Some(s), Some(o), None) => (s, o),
            _ => return Err(TableFormatError::new(num, TableFormatErrorKind::InvalidLine)),
        };

        let expr = parse_mail_addr_expr(sender_expr)
            .map_err(|_| TableFormatError::new(num, TableFormatErrorKind::InvalidRecipient))?;

        let file_name = overrides_file.strip_prefix('<')
            .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidFileSyntax))?;

        let config = format::read_config_overrides(file_name)
            .await
            .map_err(|e| {
                TableFormatError::new(num, TableFormatErrorKind::ReadConfig(Box::new(e)))
            })?;

        let entry = MailAddrOverride { expr, config };

        entries.push(entry);
    }

    Ok(RecipientOverrides { entries })
}

// Implementation note: The use of regex implies linear database search for
// matches. Later, consider using non-regex lookups where possible, and require
// linear DB walk only for the glob pattern inputs.

// An expression for matching MailAddr, used for both signing senders and
// recipient overrides.
fn parse_mail_addr_expr(s: &str) -> Result<Regex, ParseDomainError> {
    // An expression containing @ is a case-insensitive glob pattern applied to
    // an entire email address.
    // Example: me+*@*.example.com
    if s.contains('@') {
        let pieces: Vec<_> = s.split('*').map(regex::escape).collect();
        let re = format!("^(?i){}$", &pieces.join(".*"));
        return Ok(Regex::new(&re).unwrap());
    }

    // An expression starting with . is a domain-and-subdomains match pattern,
    // using lower-case ASCII form domain.
    // Example: .example.com
    if let Some(s) = s.strip_prefix('.') {
        let domain = DomainName::new(s)?.to_ascii();
        let re = format!("^(?i).*@(.+\\.)?{}$", regex::escape(&domain));
        return Ok(Regex::new(&re).unwrap());
    }

    // Finally, try a plain domain, or fall back to (again) a glob pattern.

    if let Ok(d) = DomainName::new(s) {
        // Example: example.com
        let domain = d.to_ascii();
        let re = format!("^(?i).*@{}$", regex::escape(&domain));
        return Ok(Regex::new(&re).unwrap());
    }

    // Example: sub*.example.com
    let pieces: Vec<_> = s.split('*').map(regex::escape).collect();
    let re = format!("^(?i).*@{}$", &pieces.join(".*"));
    Ok(Regex::new(&re).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mail_addr_expr_ok() {
        let expr = parse_mail_addr_expr(".example.org").unwrap();
        assert!(expr.is_match("who@example.org"));
        assert!(expr.is_match("who@mail.example.org"));
        assert!(!expr.is_match("who@.example.org"));
        assert!(!expr.is_match("who@aexample.org"));

        let expr = parse_mail_addr_expr("example.org").unwrap();
        assert!(expr.is_match("who@example.org"));
        assert!(!expr.is_match("who@mail.example.org"));
    }
}
