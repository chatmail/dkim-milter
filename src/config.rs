use crate::crypto::CachedKeyStore;
use regex::Regex;
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::{self, Display, Formatter},
    io::{self, ErrorKind},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};
use tokio::fs;
use tracing::warn;
use viadkim::{
    crypto::SigningKey,
    signature::{DomainName, Selector},
    signer::KeyId,
};

const DEFAULT_CONFIG_FILE: &str = match option_env!("DKIM_MILTER_CONFIG_FILE") {
    Some(s) => s,
    None => "/etc/dkim-milter/dkim-milter.conf",
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliOptions {
    // TODO config_file should be Option as well, default value belongs elsewhere
    pub config_file: PathBuf,
    pub log_destination: Option<LogDestination>,
    pub socket: Option<Socket>,
}

impl Default for CliOptions {
    fn default() -> Self {
        Self {
            config_file: DEFAULT_CONFIG_FILE.into(),
            log_destination: None,
            socket: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseLogDestinationError;

impl Error for ParseLogDestinationError {}

impl Display for ParseLogDestinationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse log destination")
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LogDestination {
    Journald,
    Stderr,
}

impl Default for LogDestination {
    fn default() -> Self {
        Self::Journald
    }
}

impl FromStr for LogDestination {
    type Err = ParseLogDestinationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "journald" => Ok(Self::Journald),
            "stderr" => Ok(Self::Stderr),
            _ => Err(ParseLogDestinationError),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ParseSocketError;

impl Error for ParseSocketError {}

impl Display for ParseSocketError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse socket")
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Socket {
    Inet(String),
    Unix(String),
}

impl Display for Socket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet(s) => write!(f, "inet:{s}"),
            Self::Unix(s) => write!(f, "unix:{s}"),
        }
    }
}

impl FromStr for Socket {
    type Err = ParseSocketError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(s) = s.strip_prefix("inet:") {
            Ok(Self::Inet(s.into()))
        } else if let Some(s) = s.strip_prefix("unix:") {
            Ok(Self::Unix(s.into()))
        } else {
            Err(ParseSocketError)
        }
    }
}

// TODO read log config, before other config (config reading requires logging)
#[derive(Clone, Debug)]
pub struct LogConfig {
    pub log_destination: LogDestination,
}

// TODO provisional
pub struct Config {
    pub socket: Socket,

    pub signing_senders: SigningSenders,
    pub key_store: CachedKeyStore,

    pub authserv_id: Option<String>,
}

impl Config {
    pub async fn read(opts: CliOptions) -> io::Result<Config> {
        let f = &opts.config_file;

        let file_content = fs::read_to_string(f).await?;

        let mut socket = None;
        let mut signing_keys_file = None;
        let mut signing_senders_file = None;
        let mut authserv_id = None;

        let mut keys_seen = HashSet::new();

        for (num, line) in file_content.lines().enumerate() {
            let _num = num + 1;
            let line = line.trim();

            if is_ignored_line(line) {
                continue;
            }

            match line.split_once('=') {
                Some((k, v)) => {
                    let k = k.trim();
                    let v = v.trim();

                    if keys_seen.contains(k) {
                        return Err(io::Error::new(ErrorKind::Other, "duplicate config key"));
                    }

                    match k {
                        "socket" => {
                            let value = Socket::from_str(v)
                                .map_err(|_| io::Error::new(ErrorKind::Other, "invalid socket"))?;
                            socket = Some(value);
                        }
                        "signing_keys" => {
                            signing_keys_file = Some(v);
                        }
                        "signing_senders" => {
                            signing_senders_file = Some(v);
                        }
                        "authserv_id" => {
                            authserv_id = Some(v.to_owned());
                        }
                        _ => panic!(),
                    }

                    keys_seen.insert(k);
                }
                None => {
                    return Err(io::Error::new(ErrorKind::Other, "invalid config entry"));
                }
            }
        }

        let socket = opts.socket.or(socket)
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "missing socket config"))?;

        let (key_store, signing_senders) = match (signing_keys_file, signing_senders_file) {
            (Some(signing_keys_file), Some(signing_senders_file)) => {
                read_signing_config(signing_keys_file, signing_senders_file)
                    .await?
            }
            (None, None) => {
                Default::default()
            }
            _ => {
                panic!("invalid signing config");
            }
        };

        let config = Config {
            socket,
            signing_senders,
            key_store,
            authserv_id,
        };

        Ok(config)
    }
}

// TODO
#[derive(Clone, Debug, Default)]
pub struct SigningSenders {
    pub entries: Vec<SenderEntry>,
}

#[derive(Clone, Debug)]
pub struct SenderEntry {
    pub sender_expr: Regex,
    pub domain: DomainName,
    pub selector: Selector,
    pub key_id: KeyId,
}

#[derive(Clone, Debug)]
pub struct TempSenderEntry {
    pub sender_expr: Regex,
    pub domain: DomainName,
    pub selector: Selector,
    pub key_name: String,
    pub sig_config: Option<()>,  // TODO
}

async fn read_signing_config(
    signing_keys_file: &str,
    signing_senders_file: &str,
) -> io::Result<(CachedKeyStore, SigningSenders)> {
    // Note: idea here is to warn but continue with an incomplete config and
    // only actually log an error when the milter is unable to sign a message
    // (for example, such a config does not prevent *verification* from working properly)
    // TODO warnings about not being able to sign should only be printed if signing mode is enabled

    let signing_keys = read_signing_keys_file(signing_keys_file).await?;

    if signing_keys.is_empty() {
        warn!("no signing keys available, no signing will be done");
    }

    let mut signing_senders = read_signing_senders_file(signing_senders_file).await?;

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

    // temporary map, mapping human-readable names to usize == KeyId
    let tmp: HashMap<_, _> = signing_keys.keys().zip(0..).map(|(k, v)| {
        (k.to_owned(), KeyId::new(v))
    }).collect();

    let key_store: HashMap<_, _> = signing_keys.into_iter().map(|(k, v)| {
        (tmp[&k], Arc::new(v))
    }).collect();
    let key_store = CachedKeyStore::new(key_store);

    let entries: Vec<_> = signing_senders.into_iter().map(|entry| {
        SenderEntry {
            sender_expr: entry.sender_expr,
            domain: entry.domain,
            selector: entry.selector,
            key_id: tmp[&entry.key_name],
        }
    }).collect();
    let signing_senders = SigningSenders {
        entries,
    };

    Ok((key_store, signing_senders))
}

async fn read_signing_senders_file(s: &str) -> io::Result<Vec<TempSenderEntry>> {
    let file_content = fs::read_to_string(s).await?;

    let map = parse_signing_senders_file_content(&file_content)
        .map_err(|_| io::Error::from(io::ErrorKind::Other))?;

    Ok(map)
}

fn parse_signing_senders_file_content(s: &str) -> Result<Vec<TempSenderEntry>, &'static str> {
    let mut entries = vec![];

    for line in s.lines() {
        let line = line.trim();

        if is_ignored_line(line) {
            continue;
        }

        let mut iter = line.split_ascii_whitespace();

        let sender_expr = iter.next().ok_or("invalid line")?;
        let domain = iter.next().ok_or("invalid line")?;
        let selector = iter.next().ok_or("invalid line")?;
        let key_name = iter.next().ok_or("invalid line")?;
        let _sig_config = iter.next();

        if iter.next().is_some() {
            return Err("too many fields");
        }

        // TODO
        let sender_expr = parse_sender_expr(sender_expr)
            .map_err(|_| "invalid sender expr")?;
        let domain = DomainName::new(domain)
            .map_err(|_| "invalid domain name")?;
        let selector = Selector::new(selector)
            .map_err(|_| "invalid selector")?;

        let entry = TempSenderEntry {
            sender_expr,
            domain,
            selector,
            key_name: key_name.into(),
            sig_config: None,
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
        let pieces: Vec<_> = s.split("*")
            .map(|s| regex::escape(s))
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
                let pieces: Vec<_> = s.split("*")
                    .map(|s| regex::escape(s))
                    .collect();
                let re = format!("^(?i).*@{}$", &pieces.join(".*"));
                Ok(Regex::new(&re).unwrap())
            }
        }
    }
}

async fn read_signing_keys_file(s: &str) -> io::Result<HashMap<String, SigningKey>> {
    let file_content = fs::read_to_string(s).await?;

    let map = parse_signing_keys_file_content(&file_content)
        .map_err(|_| io::Error::from(io::ErrorKind::Other))?;

    let mut result = HashMap::new();
    for (k, v) in map {
        // TODO for now, require file paths to start with '<'
        let v = v
            .trim()
            .strip_prefix('<')
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "key path not starting with '<'"))?
            .trim();

        let key_file_content = match fs::read_to_string(v).await {
            Ok(k) => k,
            Err(_e) => {
                warn!("could not read signing key \"{}\" from file, ignoring key", k);
                continue;
            }
        };

        let key = SigningKey::from_pkcs8_pem(&key_file_content)?;

        result.insert(k, key);
    }
    Ok(result)
}

fn parse_signing_keys_file_content(s: &str) -> Result<HashMap<String, String>, &'static str> {
    let mut map = HashMap::new();

    for line in s.lines() {
        let line = line.trim();

        if is_ignored_line(line) {
            continue;
        }

        let mut iter = line.split_ascii_whitespace();

        let (name, value) = match (iter.next(), iter.next(), iter.next()) {
            (Some(name), Some(value), None) => (name, value),
            _ => return Err("invalid line"),
        };

        // TODO duplicate keys

        map.insert(name.into(), value.into());
    }

    Ok(map)
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
