// DKIM Milter – milter for DKIM signing and verification
// Copyright © 2022–2024 David Bürgin <dbuergin@gluet.ch>
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
    format::ParseParamError,
    model::{
        OversignedHeaders, RejectFailure, RejectFailures, SignedFieldName,
        SignedFieldNameWithQualifier, SignedHeaders, TrustedNetworks,
    },
};
use std::{collections::HashSet, net::IpAddr, str::FromStr, time::Duration};
use viadkim::{crypto::HashAlgorithm, signer::Expiration};

pub fn parse_boolean(s: &str) -> Result<bool, ParseParamError> {
    match s {
        "yes" | "true" => Ok(true),
        "no" | "false" => Ok(false),
        _ => Err(ParseParamError::InvalidBoolean(s.into())),
    }
}

// parse u32 value and turn it into usize (preferred *internal* format) right away
pub fn parse_u32_as_usize(s: &str) -> Result<usize, ParseParamError> {
    let n = u32::from_str(s).map_err(|_| ParseParamError::InvalidU32(s.into()))?;
    let n = n.try_into().map_err(|_| ParseParamError::InvalidU32(s.into()))?;
    Ok(n)
}

pub fn parse_trusted_networks(s: &str) -> Result<TrustedNetworks, ParseParamError> {
    let mut trusted_networks = TrustedNetworks {
        trust_loopback: false,
        networks: HashSet::new(),
    };

    for value in split_at_comma(s) {
        let value = value?;
        if value == "loopback" {
            trusted_networks.trust_loopback = true;
        } else {
            let net = value
                .parse()
                .or_else(|_| value.parse::<IpAddr>().map(Into::into))
                .map_err(|_| ParseParamError::InvalidNetworkAddress(value.into()))?;
            trusted_networks.networks.insert(net);
        }
    }

    Ok(trusted_networks)
}

pub fn parse_signed_headers(s: &str) -> Result<SignedHeaders, ParseParamError> {
    if let Some(rest) = s.strip_prefix("default") {
        if rest.is_empty() {
            return Ok(SignedHeaders::PickWithDefault(vec![]));
        }

        let s = rest.trim_start();
        if let Some(rest) = s.strip_prefix(';') {
            let s = rest.trim_start();

            let mut result = parse_field_names(s)?;
            result.retain(|name| *name.as_ref() != "From");  // From already in default

            return Ok(SignedHeaders::PickWithDefault(result));
        }
    }

    if let Some(rest) = s.strip_prefix("all") {
        if rest.is_empty() {
            return Ok(SignedHeaders::All);
        }
    }

    let result = parse_field_names(s)?;

    if !result.iter().any(|n| *n.as_ref() == "From") {
        return Err(ParseParamError::SignedHeadersMissingFrom(s.into()));
    }

    Ok(SignedHeaders::Pick(result))
}

pub fn parse_oversigned_headers(s: &str) -> Result<OversignedHeaders, ParseParamError> {
    if let Some(rest) = s.strip_prefix("signed") {
        if rest.is_empty() {
            return Ok(OversignedHeaders::Signed);
        }
    }

    if let Some(rest) = s.strip_prefix("signed-extended") {
        if rest.is_empty() {
            return Ok(OversignedHeaders::Extended);
        }
    }

    let result = parse_field_names(s)?;

    Ok(OversignedHeaders::Pick(result))
}

pub fn parse_default_signed_headers(v: &str) -> Result<Vec<SignedFieldName>, ParseParamError> {
    let value = parse_field_names(v)?;

    if !value.iter().any(|n| *n.as_ref() == "From") {
        return Err(ParseParamError::SignedHeadersMissingFrom(v.into()));
    }

    Ok(value)
}

pub fn parse_default_unsigned_headers(v: &str) -> Result<Vec<SignedFieldName>, ParseParamError> {
    let value = parse_field_names(v)?;

    if value.iter().any(|n| *n.as_ref() == "From") {
        return Err(ParseParamError::FromInUnsignedHeaders(v.into()));
    }

    Ok(value)
}

pub fn parse_field_names(s: &str) -> Result<Vec<SignedFieldName>, ParseParamError> {
    let mut result = vec![];

    let mut seen = HashSet::new();

    // A trailing colon is allowed for disambiguation. For example, if someone
    // configures `oversign_headers = signed`, `signed` is a special token; if
    // someone configures `oversign_headers = signed:`, `signed` is a literal
    // header name.
    for s in split_at_colon(s) {
        let s = s?;
        let name = SignedFieldName::new(s)
            .map_err(|_| ParseParamError::InvalidFieldName(s.into()))?;
        if seen.insert(name.clone()) {
            result.push(name);
        }
        // duplicate values ignored
    }

    Ok(result)
}

pub fn parse_qualified_field_names(s: &str) -> Result<Vec<SignedFieldNameWithQualifier>, ParseParamError> {
    enum Qualifier { Bare, Plus, Asterisk }
    use Qualifier::*;

    let mut result = vec![];

    let mut seen = HashSet::new();

    for s in split_at_colon(s) {
        let mut s = s?;

        // But what if some poor soul wants to specify a header named literally
        // "Bla++" or some such? No, this is not supported.
        let qualifier = if let Some(rest) = s.strip_suffix('+') {
            s = rest.trim_end();
            Plus
        } else if let Some(rest) = s.strip_suffix('*') {
            s = rest.trim_end();
            Asterisk
        } else {
            Bare
        };

        let name = SignedFieldName::new(s)
            .map_err(|_| ParseParamError::InvalidFieldName(s.into()))?;

        if seen.insert(name.clone()) {
            match qualifier {
                Bare => result.push(SignedFieldNameWithQualifier::Bare(name)),
                Plus => result.push(SignedFieldNameWithQualifier::Plus(name)),
                Asterisk => result.push(SignedFieldNameWithQualifier::Asterisk(name)),
            }
        } else {
            return Err(ParseParamError::DuplicateFieldName(name));
        }
    }

    Ok(result)
}

pub fn parse_hash_algorithm(s: &str) -> Result<HashAlgorithm, ParseParamError> {
    let value = match s {
        "sha256" => HashAlgorithm::Sha256,
        #[cfg(feature = "pre-rfc8301")]
        "sha1" => HashAlgorithm::Sha1,
        _ => {
            return Err(ParseParamError::InvalidHashAlgorithm(s.into()));
        }
    };
    Ok(value)
}

pub fn parse_expiration(s: &str) -> Result<Expiration, ParseParamError> {
    // assumes s is already trimmed

    if s == "never" {
        return Ok(Expiration::Never);
    }

    let duration = parse_duration_secs(s)?;

    if duration.is_zero() {
        return Err(ParseParamError::InvalidDuration(s.into()));
    }

    Ok(Expiration::After(duration))
}

// Parse a duration from u32-sized seconds. Resolution in seconds, subsecond
// component not used.
pub fn parse_duration_secs(input: &str) -> Result<Duration, ParseParamError> {
    let (s, factor) = if let Some(s) = input.strip_suffix('d') {
        (s, 24 * 60 * 60)
    } else if let Some(s) = input.strip_suffix('h') {
        (s, 60 * 60)
    } else if let Some(s) = input.strip_suffix('m') {
        (s, 60)
    } else {
        let s = input.strip_suffix('s').unwrap_or(input);
        (s, 1)
    };

    let seconds = u32::from_str(s.trim_end())
        .map_err(|_| ParseParamError::InvalidDuration(input.into()))?
        .checked_mul(factor)
        .ok_or_else(|| ParseParamError::InvalidDuration(input.into()))?;

    Ok(Duration::from_secs(seconds.into()))
}

pub fn parse_reject_failures(s: &str) -> Result<RejectFailures, ParseParamError> {
    let mut set = HashSet::new();

    for value in split_at_comma(s) {
        let value = value?;
        let value = match value {
            "missing" => RejectFailure::Missing,
            "no-pass" => RejectFailure::NoPass,
            "author-mismatch" => RejectFailure::AuthorMismatch,
            "author-mismatch-strict" => RejectFailure::AuthorMismatchStrict,
            _ => return Err(ParseParamError::InvalidRejectFailure(value.into())),
        };
        set.insert(value);
    }

    Ok(RejectFailures(set))
}

// colon cannot appear in field names, so is a good choice for the separator
fn split_at_colon(value: &str) -> impl DoubleEndedIterator<Item = Result<&str, ParseParamError>> {
    split_terminator(value, ':')
}

fn split_at_comma(value: &str) -> impl DoubleEndedIterator<Item = Result<&str, ParseParamError>> {
    split_separator(value, ',')
}

fn split_separator(
    value: &str,
    sep: char,
) -> impl DoubleEndedIterator<Item = Result<&str, ParseParamError>> {
    let value = value.trim();

    let mut values = value.split(sep);

    // If the value is empty, `split` will yield one empty string slice. In that
    // case, drop this string so that the iterator becomes empty.
    if value.is_empty() {
        values.next();
    }

    values.map(|s| {
        let s = s.trim();
        if s.is_empty() {
            Err(ParseParamError::InvalidValue)
        } else {
            Ok(s)
        }
    })
}

fn split_terminator(
    value: &str,
    sep: char,
) -> impl DoubleEndedIterator<Item = Result<&str, ParseParamError>> {
    let value = value.trim();

    let mut values = value.split_terminator(sep);

    // If the value is empty, `split` will yield one empty string slice. In that
    // case, drop this string so that the iterator becomes empty.
    if value.is_empty() {
        values.next();
    }

    values.map(|s| {
        let s = s.trim();
        if s.is_empty() {
            Err(ParseParamError::InvalidValue)
        } else {
            Ok(s)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_signed_headers_ok() {
        let headers = parse_signed_headers("default").unwrap();
        assert_eq!(headers, SignedHeaders::PickWithDefault(vec![]));

        let headers = parse_signed_headers("default;").unwrap();
        assert_eq!(headers, SignedHeaders::PickWithDefault(vec![]));

        let headers = parse_signed_headers("default; From:").unwrap();
        assert_eq!(headers, SignedHeaders::PickWithDefault(vec![]));

        let headers = parse_signed_headers("default; From:To").unwrap();
        assert_eq!(
            headers,
            SignedHeaders::PickWithDefault(vec![SignedFieldName::new("To").unwrap()])
        );

        let headers = parse_signed_headers("From:").unwrap();
        assert_eq!(
            headers,
            SignedHeaders::Pick(vec![SignedFieldName::new("From").unwrap()])
        );

        assert!(parse_signed_headers("default:").is_err());
    }

    #[test]
    fn parse_oversigned_headers_ok() {
        let headers = parse_oversigned_headers("").unwrap();
        assert_eq!(headers, OversignedHeaders::Pick(vec![]));

        let headers = parse_oversigned_headers("signed").unwrap();
        assert_eq!(headers, OversignedHeaders::Signed);

        let headers = parse_oversigned_headers("signed:").unwrap();
        assert_eq!(
            headers,
            OversignedHeaders::Pick(vec![SignedFieldName::new("signed").unwrap()])
        );

        let headers = parse_oversigned_headers("signed:X").unwrap();
        assert_eq!(
            headers,
            OversignedHeaders::Pick(vec![
                SignedFieldName::new("signed").unwrap(),
                SignedFieldName::new("X").unwrap()
            ])
        );

        assert!(parse_oversigned_headers("signed::").is_err());
    }

    #[test]
    fn parse_duration_secs_ok() {
        assert_eq!(parse_duration_secs("33").unwrap(), Duration::from_secs(33));
        assert_eq!(
            parse_duration_secs("34 m").unwrap(),
            Duration::from_secs(34 * 60)
        );
    }
}
