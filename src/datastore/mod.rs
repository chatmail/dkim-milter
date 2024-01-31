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

mod filesystem;
#[cfg(feature = "sqlite")]
mod sqlite;

use crate::{
    config::model::{
        ConfigOverrides, DomainExpr, IdentityDomainExpr, IdentityExpr, LocalPartExpr,
        PartialSigningConfig,
    },
    format::MailAddr,
    util::BoxFuture,
};
use ipnet::IpNet;
use regex::Regex;
use std::{
    error::Error,
    fmt,
    net::{AddrParseError, IpAddr},
    str::FromStr,
    sync::Arc,
};
use viadkim::{
    crypto::SigningKey,
    signature::{DomainName, ParseDomainError, Selector},
};

#[derive(Debug)]
pub struct UnresolvedSenderMatch {
    domain: DomainExpr,
    selector: Selector,
    unresolved_key: Arc<str>,
    signing_config: Option<Arc<PartialSigningConfig>>,
}

impl UnresolvedSenderMatch {
    pub fn into_sender_match(self, key: Arc<SigningKey>) -> SenderMatch {
        SenderMatch {
            domain: self.domain,
            selector: self.selector,
            key,
            signing_config: self.signing_config,
        }
    }
}

#[derive(Debug)]
pub struct SenderMatch {
    pub domain: DomainExpr,
    pub selector: Selector,
    pub key: Arc<SigningKey>,
    pub signing_config: Option<Arc<PartialSigningConfig>>,
}

pub async fn find_matching_senders(
    signing_senders: &dyn SigningSendersDb,
    signing_keys: &dyn SigningKeysDb,
    sender: &MailAddr,
) -> Result<Vec<SenderMatch>, Box<dyn Error + Send + Sync>> {
    let MailAddr { local_part, domain } = sender;

    // Look up email address with domain-part converted to ASCII form.
    let sender = format!("{local_part}@{}", domain.to_ascii());

    // First, look up matching senders in the signing senders database.
    let matches = signing_senders.find_all(sender).await?;

    let key_ids: Vec<_> = matches.iter().map(|m| m.unresolved_key.clone()).collect();

    // Then, resolve (foreign) key IDs in the signing keys database.
    let resolved_keys = signing_keys.resolve_ids(key_ids).await?;

    let sender_matches = matches.into_iter()
        .zip(resolved_keys)
        .map(|(m, key)| m.into_sender_match(key))
        .collect();

    Ok(sender_matches)
}

pub type SigningSendersResult = Result<Vec<UnresolvedSenderMatch>, Box<dyn Error + Send + Sync>>;

pub trait SigningSendersDb: fmt::Debug + Send + Sync {
    // Hack(ish): *only* in combination slurp:senders and slurp:keys, must be
    // able to ensure that all senders have usable key IDs.
    fn get_cached_key_ids(&self) -> Vec<Arc<str>> {
        vec![]
    }

    fn find_all(&self, sender: String) -> BoxFuture<'_, SigningSendersResult>;
}

pub async fn read_signing_senders(
    value: &str,
) -> Result<Box<dyn SigningSendersDb>, Box<dyn Error + Send + Sync>> {
    if let Some(s) = strip_slurp_prefix_or_bare(value) {
        let db = filesystem::read_slurp_signing_senders(s).await?;
        Ok(Box::new(db))
    } else if let Some(s) = strip_file_prefix(value) {
        let db = filesystem::read_file_signing_senders(s).await?;
        Ok(Box::new(db))
    } else if has_sqlite_prefix(value) {
        #[cfg(feature = "sqlite")]
        {
            let db = sqlite::read_signing_senders(value).await?;
            Ok(Box::new(db))
        }
        #[cfg(not(feature = "sqlite"))]
        Err("sqlite data source only available when enabled".into())
    } else {
        Err("unsupported data source".into())
    }
}

pub type SigningKeysResult = Result<Vec<Arc<SigningKey>>, Box<dyn Error + Send + Sync>>;

pub trait SigningKeysDb: fmt::Debug + Send + Sync {
    // Hack(ish): see SigningSendersDb. Returns first missing key ID in `Err`.
    fn check_cached_key_ids(&self, _key_ids: Vec<Arc<str>>) -> Result<(), Arc<str>> {
        Ok(())
    }

    fn resolve_ids(&self, key_ids: Vec<Arc<str>>) -> BoxFuture<'_, SigningKeysResult>;
}

pub async fn read_signing_keys(
    value: &str,
) -> Result<Box<dyn SigningKeysDb>, Box<dyn Error + Send + Sync>> {
    if let Some(s) = strip_slurp_prefix_or_bare(value) {
        let db = filesystem::read_slurp_signing_keys(s).await?;
        Ok(Box::new(db))
    } else if let Some(s) = strip_file_prefix(value) {
        let db = filesystem::read_file_signing_keys(s).await?;
        Ok(Box::new(db))
    } else if has_sqlite_prefix(value) {
        #[cfg(feature = "sqlite")]
        {
            let db = sqlite::read_signing_keys(value).await?;
            Ok(Box::new(db))
        }
        #[cfg(not(feature = "sqlite"))]
        Err("sqlite data source only available when enabled".into())
    } else {
        Err("unsupported data source".into())
    }
}

pub type ConfigOverridesResult = Result<Vec<Arc<ConfigOverrides>>, Box<dyn Error + Send + Sync>>;

pub trait ConnectionOverridesDb: fmt::Debug + Send + Sync {
    fn find_all(&self, ip: IpAddr) -> BoxFuture<'_, ConfigOverridesResult>;
}

pub async fn read_connection_overrides(
    value: &str,
) -> Result<Box<dyn ConnectionOverridesDb>, Box<dyn Error + Send + Sync>> {
    if let Some(s) = strip_slurp_prefix_or_bare(value) {
        let db = filesystem::read_slurp_connection_overrides(s).await?;
        Ok(Box::new(db))
    } else if let Some(s) = strip_file_prefix(value) {
        let db = filesystem::read_file_connection_overrides(s).await?;
        Ok(Box::new(db))
    } else if has_sqlite_prefix(value) {
        #[cfg(feature = "sqlite")]
        {
            let db = sqlite::read_connection_overrides(value).await?;
            Ok(Box::new(db))
        }
        #[cfg(not(feature = "sqlite"))]
        Err("sqlite data source only available when enabled".into())
    } else {
        Err("unsupported data source".into())
    }
}

pub trait RecipientOverridesDb: fmt::Debug + Send + Sync {
    fn find_all(&self, recipients: Vec<String>) -> BoxFuture<'_, ConfigOverridesResult>;
}

pub async fn read_recipient_overrides(
    value: &str,
) -> Result<Box<dyn RecipientOverridesDb>, Box<dyn Error + Send + Sync>> {
    if let Some(s) = strip_slurp_prefix_or_bare(value) {
        let db = filesystem::read_slurp_recipient_overrides(s).await?;
        Ok(Box::new(db))
    } else if let Some(s) = strip_file_prefix(value) {
        let db = filesystem::read_file_recipient_overrides(s).await?;
        Ok(Box::new(db))
    } else if has_sqlite_prefix(value) {
        #[cfg(feature = "sqlite")]
        {
            let db = sqlite::read_recipient_overrides(value).await?;
            Ok(Box::new(db))
        }
        #[cfg(not(feature = "sqlite"))]
        Err("sqlite data source only available when enabled".into())
    } else {
        Err("unsupported data source".into())
    }
}

// The *slurp* data source is also used as a fallback for values that are not
// prefixed with a data source spec.
fn strip_slurp_prefix_or_bare(s: &str) -> Option<&str> {
    fn has_datasource(s: &str) -> bool {
        matches!(
            s.split_once(':'),
            Some((s, _)) if !s.is_empty() && s.chars().all(|c| c.is_alphanumeric())
        )
    }

    strip_slurp_prefix(s).or_else(|| if has_datasource(s) { None } else { Some(s) })
}

fn strip_slurp_prefix(s: &str) -> Option<&str> {
    s.strip_prefix('<').or_else(|| s.strip_prefix("slurp:"))
}

fn strip_file_prefix(s: &str) -> Option<&str> {
    s.strip_prefix("file:")
}

fn has_sqlite_prefix(s: &str) -> bool {
    s.starts_with("sqlite:")
}

pub fn parse_network_expr(s: &str) -> Result<IpNet, AddrParseError> {
    IpNet::from_str(s).or_else(|_| IpAddr::from_str(s).map(Into::into))
}

pub fn parse_domain_expr(s: &str) -> Result<DomainExpr, ParseDomainError> {
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

// Implementation note: The use of regex implies linear database search for
// matches. Later, consider using non-regex lookups where possible, and require
// linear DB walk only for the glob pattern inputs.

// An expression for matching MailAddr, used for both signing senders and
// recipient overrides.
pub fn parse_mail_addr_expr(s: &str) -> Result<Regex, ParseDomainError> {
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

fn get_recipient_ascii_domain<'a>(
    recipient: &str,
    cached_recipient: &'a mut Option<Result<String, ()>>,
) -> &'a mut Result<String, ()> {
    cached_recipient.get_or_insert_with(|| {
        recipient
            .rsplit_once('@')
            .and_then(|(l, d)| {
                let domain = DomainName::new(d).ok()?.to_ascii();
                Some(format!("{l}@{domain}"))
            })
            .ok_or(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_slurp_prefix_or_bare_ok() {
        assert_eq!(strip_slurp_prefix_or_bare("<x"), Some("x"));
        assert_eq!(strip_slurp_prefix_or_bare("slurp:x"), Some("x"));
        assert_eq!(strip_slurp_prefix_or_bare("slurp:"), Some(""));
        assert_eq!(strip_slurp_prefix_or_bare("bla:x"), None);
        assert_eq!(strip_slurp_prefix_or_bare("bla:"), None);
        assert_eq!(strip_slurp_prefix_or_bare(":x"), Some(":x"));
        assert_eq!(strip_slurp_prefix_or_bare("bla"), Some("bla"));
        assert_eq!(strip_slurp_prefix_or_bare(""), Some(""));
    }

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
