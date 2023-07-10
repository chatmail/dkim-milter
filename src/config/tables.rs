use crate::config::{
    format,
    model::{OverrideEntry, PartialSigningConfig, SigningOverrides},
    ConfigError,
};
use regex::Regex;
use std::{
    collections::HashMap,
    error::Error,
    fmt::{self, Display, Formatter},
    io::{self, ErrorKind},
    path::PathBuf,
};
use tokio::fs;
use viadkim::{
    crypto::SigningKey,
    signature::{DomainName, Selector},
};

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
            ReadKeyFile(_) | ReadConfig(_) => Ok(()),
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

async fn read_signing_key(
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

    let key = SigningKey::from_pkcs8_pem(&key_file_content)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

    Ok(key)
}

pub async fn read_signing_senders_table(
    file_name: &str,
) -> Result<Vec<TempSenderEntry>, TableError> {
    async {
        let file_content = fs::read_to_string(file_name).await?;

        let map = parse_signing_senders_table(&file_content).await?;

        Ok(map)
    }
    .await
    .map_err(|e| TableError::new(file_name, e))
}

pub async fn read_recipient_overrides_table(
    file_name: &str,
) -> Result<SigningOverrides, TableError> {
    async {
        let file_content = fs::read_to_string(file_name).await?;

        let overrides = parse_recipient_overrides_table(&file_content).await?;

        Ok(SigningOverrides { entries: overrides })
    }
    .await
    .map_err(|e| TableError::new(file_name, e))
}

#[derive(Debug)]
pub struct TempSenderEntry {
    pub sender_expr: Regex,
    pub domain: DomainName,
    pub selector: Selector,
    pub key_name: String,
    pub signing_config: Option<PartialSigningConfig>,
}

async fn parse_signing_senders_table(
    file_content: &str,
) -> Result<Vec<TempSenderEntry>, TableFormatError> {
    let mut entries = vec![];

    let iter = format::lines(file_content);

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

                let config = format::read_signing_config_overrides(sig_config_file)
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

async fn parse_signing_keys_table(
    file_content: &str,
) -> Result<HashMap<String, SigningKey>, TableFormatError> {
    let mut map = HashMap::new();

    let iter = format::lines(file_content);

    for (num, line) in iter {
        let mut iter = line.split_ascii_whitespace();

        let (name, value) = match (iter.next(), iter.next(), iter.next()) {
            (Some(name), Some(value), None) => (name, value),
            _ => {
                return Err(TableFormatError::new(num, TableFormatErrorKind::InvalidLine));
            }
        };

        // TODO duplicate keys

        // TODO for now, require file paths to start with '<'
        let v = value
            .trim()
            .strip_prefix('<')
            .ok_or_else(|| TableFormatError::new(num, TableFormatErrorKind::InvalidFileSyntax))?
            .trim();

        let key = read_signing_key(v)
            .await
            .map_err(|e| TableFormatError::new(num, TableFormatErrorKind::ReadKeyFile(e)))?;

        map.insert(name.into(), key);
    }

    Ok(map)
}

async fn parse_recipient_overrides_table(
    file_content: &str,
) -> Result<Vec<OverrideEntry>, TableFormatError> {
    let mut entries = vec![];

    let iter = format::lines(file_content);

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

        let config = format::read_signing_config_overrides(v).await.map_err(|e| {
            TableFormatError::new(num, TableFormatErrorKind::ReadConfig(Box::new(e)))
        })?;

        let entry = OverrideEntry { expr, config };

        entries.push(entry);
    }

    Ok(entries)
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
