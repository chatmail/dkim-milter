use crate::config::{
    format::ParseParamError,
    model::{
        Expiration, OversignedHeaders, RejectFailure, RejectFailures, SignedFieldName,
        SignedHeaders, TrustedNetworks,
    },
};
use std::{collections::HashSet, net::IpAddr, str::FromStr, time::Duration};
use viadkim::crypto::HashAlgorithm;

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
                .or_else(|_| value.parse::<IpAddr>().map(From::from))
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

    if let Some(rest) = s.strip_prefix("exhaustive") {
        if rest.is_empty() {
            return Ok(OversignedHeaders::Exhaustive);
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

    let mut seen: HashSet<SignedFieldName> = HashSet::new();

    // A trailing colon is allowed for disambiguation. For example, if someone
    // configures `oversigned_headers = signed`, `signed` is a special token; if
    // someone configures `oversigned_headers = signed:`, `signed` is a literal
    // header name.
    for s in split_at_colon(s) {
        let s = s?;
        let name = SignedFieldName::new(s)
            .map_err(|_| ParseParamError::InvalidFieldName(s.into()))?;
        if seen.insert(name.clone()) {
            result.push(name);
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
        // TODO rename error
        return Err(ParseParamError::InvalidExpiration(s.into()));
    }

    Ok(Expiration::After(duration))
}

// Parse a duration from u32-sized seconds. Resolution in seconds, subsecond
// component not used.
pub fn parse_duration_secs(input: &str) -> Result<Duration, ParseParamError> {
    let seconds = if let Some(s) = input.strip_suffix('d') {
        let days = u32::from_str(s.trim_end())
            .map_err(|_| ParseParamError::InvalidDuration(input.into()))?;
        days.checked_mul(24 * 60 * 60)
            .ok_or_else(|| ParseParamError::InvalidDuration(input.into()))?
    } else if let Some(s) = input.strip_suffix('h') {
        let hours = u32::from_str(s.trim_end())
            .map_err(|_| ParseParamError::InvalidDuration(input.into()))?;
        hours.checked_mul(60 * 60)
            .ok_or_else(|| ParseParamError::InvalidDuration(input.into()))?
    } else if let Some(s) = input.strip_suffix('m') {
        let minutes = u32::from_str(s.trim_end())
            .map_err(|_| ParseParamError::InvalidDuration(input.into()))?;
        minutes.checked_mul(60)
            .ok_or_else(|| ParseParamError::InvalidDuration(input.into()))?
    } else {
        let s = input.strip_suffix('s').unwrap_or(input);
        u32::from_str(s.trim_end())
            .map_err(|_| ParseParamError::InvalidDuration(input.into()))?
    };

    Ok(Duration::from_secs(seconds.into()))
}

pub fn parse_reject_failures(s: &str) -> Result<RejectFailures, ParseParamError> {
    let mut set = HashSet::new();

    for value in split_at_comma(s) {
        let value = value?;
        let value = match value {
            "missing" => RejectFailure::Missing,
            "failing" => RejectFailure::Failing,
            "author-mismatch" => RejectFailure::AuthorMismatch,
            _ => return Err(ParseParamError::InvalidRejectFailure(value.into())),
        };
        set.insert(value);
    }

    Ok(RejectFailures(set))
}

// colon cannot appear in field names, so is a good choice for the separator
fn split_at_colon(value: &str) -> impl Iterator<Item = Result<&str, ParseParamError>> {
    split_terminator(value, ':')
}

fn split_at_comma(value: &str) -> impl Iterator<Item = Result<&str, ParseParamError>> {
    split_separator(value, ',')
}

fn split_separator(value: &str, sep: char) -> impl Iterator<Item = Result<&str, ParseParamError>> {
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

fn split_terminator(value: &str, sep: char) -> impl Iterator<Item = Result<&str, ParseParamError>> {
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
}
