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

use std::{
    borrow::Cow,
    cmp,
    error::Error,
    fmt::{self, Display, Formatter},
    net::IpAddr,
    str::{self, FromStr},
};
use viadkim::signature::DomainName;

// Note: Some things copied from SPF Milter, may consolidate later.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailAddr {
    pub local_part: String,
    pub domain: DomainName,
}

impl Display for MailAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local_part, self.domain)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ParseAddrSpecError;

impl Display for ParseAddrSpecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse mailbox")
    }
}

impl Error for ParseAddrSpecError {}

// RFC 5322, section 3.6.2

// sender = "Sender:" mailbox CRLF
pub fn parse_sender_address(input: &[u8]) -> Result<AddrSpec, ParseAddrSpecError> {
    let (mailbox, rest) = parse_mailbox(input).ok_or(ParseAddrSpecError)?;

    if !rest.is_empty() {
        return Err(ParseAddrSpecError);
    }

    Ok(mailbox)
}

// from = "From:" mailbox-list CRLF
pub fn parse_from_addresses(input: &[u8]) -> Result<Vec<AddrSpec>, ParseAddrSpecError> {
    let (mailboxes, rest) = parse_mailboxes(input).ok_or(ParseAddrSpecError)?;

    if !rest.is_empty() {
        return Err(ParseAddrSpecError);
    }

    Ok(mailboxes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddrSpec {
    local_part: String,
    domain_part: DomainPart,
}

impl AddrSpec {
    pub fn into_mail_addr(self) -> Option<MailAddr> {
        match self {
            Self {
                local_part,
                domain_part: DomainPart::DomainName(domain),
            } => Some(MailAddr { local_part, domain }),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainPart {
    DomainName(DomainName),
    DomainLiteral(IpAddr),
}

// Design note: Considerable effort is spent to allow non-UTF-8 bytes in certain
// places, eg in display-name. This is to allow the occasional ill-formed
// submission (eg containing a Latin 1 name), where it is not harmful, to be
// processed transparently.

// Implementation note: Parsing uses byte slices at first, to allow for
// non-UTF-8 bytes. However, as soon as stricter validity is required the byte
// slice will be (partially) converted to UTF-8. This approach is really rather
// complicated, revisit?

// RFC 5322, section 3.4
// (But note the update in RFC 6854, which is not useful in our application, and
// therefore ignored.)

// mailbox-list = (mailbox *("," mailbox))
fn parse_mailboxes(input: &[u8]) -> Option<(Vec<AddrSpec>, &[u8])> {
    let (mailbox, mut rest) = parse_mailbox(input)?;

    let mut result = vec![mailbox];
    while let Some((mailbox, restx)) = rest.strip_prefix(b",").and_then(parse_mailbox) {
        result.push(mailbox);
        rest = restx;
    }

    Some((result, rest))
}

// mailbox = name-addr / addr-spec
fn parse_mailbox(input: &[u8]) -> Option<(AddrSpec, &[u8])> {
    // Surrounding [CFWS] is stripped here but is strictly speaking part of the
    // contained productions.

    let input = strip_cfws_loose(input).unwrap_or(input);

    let (addr, rest) = parse_mailbox_contents(input)?;

    let rest = strip_cfws_loose(rest).unwrap_or(rest);

    Some((addr, rest))
}

// name-addr = [display-name] angle-addr
// display-name = phrase
// phrase = 1*word
// word = atom / quoted-string
// atom = [CFWS] 1*atext [CFWS]
fn parse_mailbox_contents(input: &[u8]) -> Option<(AddrSpec, &[u8])> {
    // After the optional CFWS has been stripped, now mailbox contents can begin
    // with addr-spec, angle-addr, or display-name.

    // If we are looking at an angle-addr or an addr-spec, both of which must be
    // UTF-8, return right away.
    if let Some(input_str) = next_utf8_chunk(input) {
        if let Some((addr, rest)) = parse_angle_addr(input_str)
            .or_else(|| parse_addr_spec(input_str))
        {
            let i = strip_suffix(input_str, rest).len();
            let rest = &input[i..];
            return Some((addr, rest));
        }
    }

    // Else, we must be looking at a display-name. Recognise quoted-string,
    // CFWS, and else mostly anything until "<".

    let f = |input| {
        strip_quoted_string_loose(input)
            .or_else(|| strip_display_name_content(input))
            .map(|s| strip_cfws_loose(s).unwrap_or(s))
    };
    let mut s = f(input)?;
    while let Some(snext) = f(s) {
        s = snext;
    }

    // Now s must be looking at an angle-addr.

    if let Some(s_str) = next_utf8_chunk(s) {
        if let Some((addr, rest)) = parse_angle_addr(s_str) {
            let i = strip_suffix(s_str, rest).len();
            let rest = &s[i..];
            return Some((addr, rest));
        }
    }

    None
}

fn strip_display_name_content(input: &[u8]) -> Option<&[u8]> {
    // Any printable bytes except the start of angle-addr, quoted-string, or
    // comment from CFWS.
    strip_many(input, |c| {
        c.is_ascii_graphic() && !matches!(c, b'<' | b'"' | b'(') || !c.is_ascii()
    })
}

// angle-addr = [CFWS] "<" addr-spec ">" [CFWS]
// (Surrounding [CFWS] has been stripped already.)
fn parse_angle_addr(input: &str) -> Option<(AddrSpec, &str)> {
    let s = input.strip_prefix('<')?;

    let s = strip_cfws(s).unwrap_or(s);

    let (addr, rest) = parse_addr_spec(s)?;

    let s = strip_cfws(rest).unwrap_or(rest);

    let rest = s.strip_prefix('>')?;

    Some((addr, rest))
}

// addr-spec = local-part "@" domain
// local-part = dot-atom / quoted-string
// domain = dot-atom / domain-literal
// (Surrounding [CFWS] has been stripped already.)
fn parse_addr_spec(input: &str) -> Option<(AddrSpec, &str)> {
    let rest = strip_dot_atom(input).or_else(|| strip_quoted_string(input))?;
    let local_part = strip_suffix(input, rest);

    let s = strip_cfws(rest).unwrap_or(rest);

    let s = s.strip_prefix('@')?;

    let s = strip_cfws(s).unwrap_or(s);

    // For both domain names and literals, require that the value be parsable as
    // a `DomainName` or `IpAddr`, which is stricter than what is syntactically
    // possible.
    // Compare RFC 5322, section 3.4.1: ‘A liberal syntax for the domain portion
    // of addr-spec is given here. However, the domain portion contains
    // addressing information […]. It is therefore incumbent upon
    // implementations to conform to the syntax of addresses for the context in
    // which they are used.’

    let (domain_part, rest) = if let Some(rest) = strip_dot_atom(s) {
        let domain = strip_suffix(s, rest);
        let domain = DomainName::new(domain).ok()?;
        (DomainPart::DomainName(domain), rest)
    } else if let Some((domain_literal, rest)) = parse_domain_literal(s) {
        let ip = IpAddr::from_str(domain_literal).ok()?;
        (DomainPart::DomainLiteral(ip), rest)
    } else {
        return None;
    };

    let addr = AddrSpec {
        local_part: local_part.into(),
        domain_part,
    };

    Some((addr, rest))
}

// domain-literal = [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
// (Surrounding [CFWS] has been stripped already.)
fn parse_domain_literal(input: &str) -> Option<(&str, &str)> {
    let s = input.strip_prefix('[')?;

    let s = strip_fws(s).unwrap_or(s);

    // Unlike in the ABNF, FWS inside dtext items is not allowed.
    let rest = strip_dtext(s)?;
    let literal = strip_suffix(s, rest);

    let s = strip_fws(rest).unwrap_or(rest);

    let s = s.strip_prefix(']')?;

    Some((literal, s))
}

fn strip_dtext(input: &str) -> Option<&str> {
    input
        .strip_prefix(is_dtext)
        .map(|s| s.trim_start_matches(is_dtext))
}

// Printable US-ASCII characters not including "[", "]", or "\"
fn is_dtext(c: char) -> bool {
    c.is_ascii_graphic() && !matches!(c, '[' | '\\' | ']')
}

// RFC 5322, section 3.2

// CFWS = (1*([FWS] comment) [FWS]) / FWS
pub fn strip_cfws(input: &str) -> Option<&str> {
    enum State { Fws, Comment }

    let (mut s, mut state) = if let Some(s) = strip_fws(input) {
        (s, State::Fws)
    } else if let Some(s) = strip_comment(input) {
        (s, State::Comment)
    } else {
        return None;
    };

    loop {
        match state {
            State::Fws => {
                if let Some(snext) = strip_comment(s) {
                    s = snext;
                    state = State::Comment;
                } else {
                    break;
                }
            }
            State::Comment => {
                if let Some(snext) = strip_fws(s) {
                    s = snext;
                    state = State::Fws;
                } else if let Some(snext) = strip_comment(s) {
                    s = snext;
                } else {
                    break;
                }
            }
        }
    }

    Some(s)
}

// FWS = ([*WSP CRLF] 1*WSP)
fn strip_fws(input: &str) -> Option<&str> {
    // This is different from SPF Milter, where probably this should be adopted
    // as it’s simpler and more intuitive.
    if let Some(s) = strip_wsp(input) {
        s.strip_prefix(CRLF).and_then(strip_wsp).or(Some(s))
    } else {
        input.strip_prefix(CRLF).and_then(strip_wsp)
    }
}

fn strip_wsp(input: &str) -> Option<&str> {
    input
        .strip_prefix(is_wsp)
        .map(|s| s.trim_start_matches(is_wsp))
}

// comment = "(" *([FWS] ccontent) [FWS] ")"
fn strip_comment(input: &str) -> Option<&str> {
    enum State { Content, Fws }

    let mut s = input.strip_prefix('(')?;
    let mut state = State::Content;

    loop {
        match state {
            State::Content => {
                if let Some(snext) = s.strip_prefix(')') {
                    s = snext;
                    break;
                } else if let Some(snext) = strip_ccontent(s) {
                    s = snext;
                } else if let Some(snext) = strip_fws(s) {
                    s = snext;
                    state = State::Fws;
                } else {
                    return None;
                }
            }
            State::Fws => {
                if let Some(snext) = s.strip_prefix(')') {
                    s = snext;
                    break;
                } else if let Some(snext) = strip_ccontent(s) {
                    s = snext;
                    state = State::Content;
                } else {
                    return None;
                }
            }
        }
    }

    Some(s)
}

// ccontent = ctext / quoted-pair / comment
fn strip_ccontent(input: &str) -> Option<&str> {
    strip_ctext(input)
        .or_else(|| strip_quoted_pair(input))
        .or_else(|| strip_comment(input))
}

fn strip_ctext(input: &str) -> Option<&str> {
    input.strip_prefix(is_ctext)
}

fn is_ctext(c: char) -> bool {
    c.is_ascii_graphic() && !matches!(c, '(' | ')' | '\\') || !c.is_ascii()
}

pub fn strip_cfws_loose(input: &[u8]) -> Option<&[u8]> {
    enum State { Fws, Comment }

    let (mut s, mut state) = if let Some(s) = strip_fws_bytes(input) {
        (s, State::Fws)
    } else if let Some(s) = strip_comment_loose(input) {
        (s, State::Comment)
    } else {
        return None;
    };

    loop {
        match state {
            State::Fws => {
                if let Some(snext) = strip_comment_loose(s) {
                    s = snext;
                    state = State::Comment;
                } else {
                    break;
                }
            }
            State::Comment => {
                if let Some(snext) = strip_fws_bytes(s) {
                    s = snext;
                    state = State::Fws;
                } else {
                    break;
                }
            }
        }
    }

    Some(s)
}

fn strip_fws_bytes(input: &[u8]) -> Option<&[u8]> {
    const CRLF_: &[u8] = CRLF.as_bytes();

    if let Some(s) = strip_wsp_bytes(input) {
        s.strip_prefix(CRLF_).and_then(strip_wsp_bytes).or(Some(s))
    } else {
        input.strip_prefix(CRLF_).and_then(strip_wsp_bytes)
    }
}

fn strip_wsp_bytes(input: &[u8]) -> Option<&[u8]> {
    strip_many(input, is_wsp_b)
}

fn strip_comment_loose(input: &[u8]) -> Option<&[u8]> {
    enum State { Content, Fws }

    let mut s = input.strip_prefix(b"(")?;
    let mut state = State::Content;

    loop {
        match state {
            State::Content => {
                if let Some(snext) = s.strip_prefix(b")") {
                    s = snext;
                    break;
                } else if let Some(snext) = strip_ccontent_loose(s) {
                    s = snext;
                } else if let Some(snext) = strip_fws_bytes(s) {
                    s = snext;
                    state = State::Fws;
                } else {
                    return None;
                }
            }
            State::Fws => {
                if let Some(snext) = s.strip_prefix(b")") {
                    s = snext;
                    break;
                } else if let Some(snext) = strip_ccontent_loose(s) {
                    s = snext;
                    state = State::Content;
                } else {
                    return None;
                }
            }
        }
    }

    Some(s)
}

fn strip_ccontent_loose(input: &[u8]) -> Option<&[u8]> {
    strip_ctext_loose(input)
        .or_else(|| strip_quoted_pair_bytes(input))
        .or_else(|| strip_comment_loose(input))
}

fn strip_ctext_loose(input: &[u8]) -> Option<&[u8]> {
    strip_many(input, is_ctext_loose)
}

fn is_ctext_loose(c: &u8) -> bool {
    c.is_ascii_graphic() && !matches!(c, b'(' | b')' | b'\\') || !c.is_ascii()
}

pub fn is_dot_atom(s: &str) -> bool {
    strip_dot_atom(s) == Some("")
}

// dot-atom = [CFWS] dot-atom-text [CFWS]
// dot-atom-text = 1*atext *("." 1*atext)
// (This is actually dot-atom-text, as we strip surrounding CFWS elsewhere.)
fn strip_dot_atom(input: &str) -> Option<&str> {
    let mut s = strip_atext(input)?;
    while let Some(snext) = s.strip_prefix('.').and_then(strip_atext) {
        s = snext;
    }
    Some(s)
}

fn strip_atext(input: &str) -> Option<&str> {
    input
        .strip_prefix(is_atext)
        .map(|s| s.trim_start_matches(is_atext))
}

fn is_atext(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '/' | '=' | '?' | '^' | '_' | '`'
                | '{' | '|' | '}' | '~'
        )
        || !c.is_ascii()
}

pub fn is_quoted_string(s: &str) -> bool {
    strip_quoted_string(s) == Some("")
}

// quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]
// (The surrounding [CFWS] has been stripped elsewhere.)
fn strip_quoted_string(input: &str) -> Option<&str> {
    enum State { Content, Fws }

    let mut s = input.strip_prefix('"')?;
    let mut state = State::Content;

    loop {
        match state {
            State::Content => {
                if let Some(snext) = s.strip_prefix('"') {
                    s = snext;
                    break;
                } else if let Some(snext) = strip_qcontent(s) {
                    s = snext;
                } else if let Some(snext) = strip_fws(s) {
                    s = snext;
                    state = State::Fws;
                } else {
                    return None;
                }
            }
            State::Fws => {
                if let Some(snext) = s.strip_prefix('"') {
                    s = snext;
                    break;
                } else if let Some(snext) = strip_qcontent(s) {
                    s = snext;
                    state = State::Content;
                } else {
                    return None;
                }
            }
        }
    }

    Some(s)
}

// qcontent = qtext / quoted-pair
fn strip_qcontent(input: &str) -> Option<&str> {
    input
        .strip_prefix(is_qtext)
        .or_else(|| strip_quoted_pair(input))
}

fn is_qtext(c: char) -> bool {
    c.is_ascii_graphic() && !matches!(c, '"' | '\\') || !c.is_ascii()
}

// quoted-pair = ("\" (VCHAR / WSP))
fn strip_quoted_pair(input: &str) -> Option<&str> {
    input
        .strip_prefix('\\')
        .and_then(|s| s.strip_prefix(|c| is_vchar(c) || is_wsp(c)))
}

fn strip_quoted_string_loose(input: &[u8]) -> Option<&[u8]> {
    enum State { Content, Fws }

    let mut s = input.strip_prefix(b"\"")?;
    let mut state = State::Content;

    loop {
        match state {
            State::Content => {
                if let Some(snext) = s.strip_prefix(b"\"") {
                    s = snext;
                    break;
                } else if let Some(snext) = strip_qcontent_loose(s) {
                    s = snext;
                } else if let Some(snext) = strip_fws_bytes(s) {
                    s = snext;
                    state = State::Fws;
                } else {
                    return None;
                }
            }
            State::Fws => {
                if let Some(snext) = s.strip_prefix(b"\"") {
                    s = snext;
                    break;
                } else if let Some(snext) = strip_qcontent_loose(s) {
                    s = snext;
                    state = State::Content;
                } else {
                    return None;
                }
            }
        }
    }

    Some(s)
}

fn strip_qcontent_loose(input: &[u8]) -> Option<&[u8]> {
    strip_qtext_loose(input).or_else(|| strip_quoted_pair_bytes(input))
}

fn strip_qtext_loose(input: &[u8]) -> Option<&[u8]> {
    strip_many(input, is_qtext_loose)
}

fn is_qtext_loose(c: &u8) -> bool {
    c.is_ascii_graphic() && !matches!(c, b'"' | b'\\') || !c.is_ascii()
}

fn strip_quoted_pair_bytes(input: &[u8]) -> Option<&[u8]> {
    fn next_char(input: &[u8]) -> Option<char> {
        let max = cmp::min(input.len(), 4);
        next_utf8_chunk(&input[..max]).map(|s| s.chars().next().unwrap())
    }

    let i = input.strip_prefix(b"\\")?;
    // Require valid UTF-8 character on the right-hand side.
    if let Some(c) = next_char(i).filter(|&c| is_vchar(c) || is_wsp(c)) {
        return Some(&i[c.len_utf8()..]);
    }
    None
}

// RFC 2045, section 5.1

// value := token / quoted-string
pub fn strip_mime_value(input: &[u8]) -> Option<&[u8]> {
    // Require MIME values to be UTF-8 only.
    if let Some(input_str) = next_utf8_chunk(input) {
        if let Some(rest) = strip_token(input_str).or_else(|| strip_quoted_string(input_str)) {
            let i = strip_suffix(input_str, rest).len();
            let rest = &input[i..];
            return Some(rest);
        }
    }

    None
}

fn is_token(s: &str) -> bool {
    strip_token(s) == Some("")
}

// token := 1*<any (US-ASCII) CHAR except SPACE, CTLs, or tspecials>
fn strip_token(input: &str) -> Option<&str> {
    fn is_token(c: char) -> bool {
        c.is_ascii_graphic()
            && !matches!(
                c,
                '(' | ')' | '<' | '>' | '@' | ',' | ';' | ':' | '\\' | '"' | '/' | '[' | ']' | '?' | '='
            )
    }

    input
        .strip_prefix(is_token)
        .map(|s| s.trim_start_matches(is_token))
}

fn strip_many(input: &[u8], pred: impl Fn(&u8) -> bool) -> Option<&[u8]> {
    let n = input.iter().take_while(|&c| pred(c)).count();
    if n > 0 {
        Some(&input[n..])
    } else {
        None
    }
}

const CRLF: &str = "\r\n";

fn is_wsp(c: char) -> bool {
    matches!(c, ' ' | '\t')
}

fn is_wsp_b(c: &u8) -> bool {
    matches!(c, b' ' | b'\t')
}

fn is_vchar(c: char) -> bool {
    c.is_ascii_graphic() || !c.is_ascii()
}

pub fn strip_suffix<'a>(s: &'a str, suffix: &str) -> &'a str {
    debug_assert!(s.ends_with(suffix));
    &s[..(s.len() - suffix.len())]
}

fn next_utf8_chunk(input: &[u8]) -> Option<&str> {
    match str::from_utf8(input) {
        Ok(s) => {
            if !s.is_empty() {
                return Some(s);
            }
        }
        Err(e) => {
            let i = e.valid_up_to();
            if i > 0 {
                return Some(str::from_utf8(&input[..i]).unwrap());
            }
        }
    }

    None
}

/// Encodes the given string as an RFC 2045 `value`.
pub fn encode_mime_value(s: &str) -> Cow<'_, str> {
    if is_token(s) {
        s.into()
    } else {
        encode_quoted_string(s).into()
    }
}

/// Encodes the given string as an RFC 5322 `quoted-string`. This produces one
/// unbroken quoted string as a unit, without recognising or introducing folding
/// whitespace.
fn encode_quoted_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');
    for c in s.chars() {
        if is_qtext(c) || is_wsp(c) {
            result.push(c);
        } else if matches!(c, '"' | '\\') {
            result.push('\\');
            result.push(c);
        } else {
            result.extend(c.escape_default());
        }
    }
    result.push('"');
    result
}

/// Decodes the given quoted string and returns its (semantic) content. The
/// input must be a valid quoted string.
pub fn decode_quoted_string(s: &str) -> String {
    debug_assert!(is_quoted_string(s));

    // Strip surrounding double quotes.
    let s = &s[1..(s.len() - 1)];

    let mut result = String::with_capacity(s.len());

    // Copy the string into the result, but
    // - remove CRLF (which is always part of FWS); and
    // - replace quoted-pair with the quoted character.
    for part in s.split(CRLF) {
        let mut escape = false;
        for c in part.chars() {
            if escape {
                escape = false;
                result.push(c);
            } else if c == '\\' {
                escape = true;
            } else {
                result.push(c);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sender_address_ok() {
        assert_eq!(
            parse_sender_address(b" ( x(\xfa)) hello@example.com(z) "),
            Ok(AddrSpec {
                local_part: "hello".to_owned(),
                domain_part: DomainPart::DomainName(DomainName::new("example.com").unwrap()),
            })
        );
        assert_eq!(
            parse_sender_address(b" ( x(\xfa)) hello@example.com(z) trailing"),
            Err(ParseAddrSpecError)
        );
        assert_eq!(
            parse_sender_address(b" ( x(\xfa)) hello@[2.3.4.5] "),
            Ok(AddrSpec {
                local_part: "hello".to_owned(),
                domain_part: DomainPart::DomainLiteral(IpAddr::from([2, 3, 4, 5])),
            })
        );
    }

    #[test]
    fn parse_from_addresses_ok() {
        assert_eq!(
            parse_from_addresses(b"  (all right:)\t \"let's see\" <does@this.work> "),
            Ok(vec![AddrSpec {
                local_part: "does".to_owned(),
                domain_part: DomainPart::DomainName(DomainName::new("this.work").unwrap()),
            }])
        );
        assert_eq!(
            parse_from_addresses(b"  (all right:)\t \"let's see\" <does@this.1213121> "),
            Err(ParseAddrSpecError)
        );
    }

    #[test]
    fn parse_mailbox_ok() {
        assert_eq!(
            // display name contains "Rüedi" in Latin1 (= invalid UTF-8)
            parse_mailbox(b"  (\r\n hoi R\xfcedi (R\xc3\xbcedi in Latin1) )\t \"hei\" <ruedi@go> "),
            Some((
                AddrSpec {
                    local_part: "ruedi".into(),
                    domain_part: DomainPart::DomainName(DomainName::new("go").unwrap()),
                },
                &b""[..]
            ))
        );
    }

    #[test]
    fn parse_angle_addr_ok() {
        assert_eq!(
            parse_angle_addr("<me@what.com>"),
            Some((
                AddrSpec {
                    local_part: "me".into(),
                    domain_part: DomainPart::DomainName(DomainName::new("what.com").unwrap()),
                },
                ""
            ))
        );
        assert_eq!(
            parse_angle_addr("<me@[\r\n\t1.2.3.4]>"),
            Some((
                AddrSpec {
                    local_part: "me".into(),
                    domain_part: DomainPart::DomainLiteral(IpAddr::from([1, 2, 3, 4])),
                },
                ""
            ))
        );
        assert_eq!(
            parse_angle_addr("<\"who \" @\twhat.x>"),
            Some((
                AddrSpec {
                    local_part: "\"who \"".into(),
                    domain_part: DomainPart::DomainName(DomainName::new("what.x").unwrap()),
                },
                ""
            ))
        );
    }

    #[test]
    fn strip_cfws_ok() {
        let examples = [
            ("", None),
            ("x", None),
            (" ", Some("")),
            (" \r\n\t", Some("")),
            (" \r\n", Some("\r\n")),
            ("()", Some("")),
            ("(a (b) c)", Some("")),
            ("(a(bc)", None),
            ("(a) (b\r\n\t) (c) ", Some("")),
            ("(x\\y\\ 你\\好)", Some("")),
        ];

        for (input, expected) in examples {
            let actual = strip_cfws(input);
            assert_eq!(actual, expected);

            let actual = strip_cfws_loose(input.as_bytes());
            let expected = expected.map(|s| s.as_bytes());
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn strip_cfws_loose_ok() {
        assert_eq!(strip_cfws_loose(b"  (a\xfa)x"), Some(&b"x"[..]));

        // quoted-pair, backslash followed by well-formed UTF-8 sequence:
        assert_eq!(strip_cfws_loose(b"(\\\xe4\xbd\xa0)"), Some(&b""[..]));
        // not a quoted-pair, backslash followed by stray byte:
        assert_eq!(strip_cfws_loose(b"(\\\xfa)"), None);
    }
}
