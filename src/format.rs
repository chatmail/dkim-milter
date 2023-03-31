use std::{
    fmt::{self, Display, Formatter},
    str,
};
use viadkim::signature::DomainName;

const CRLF: &[u8] = b"\r\n";

// pub type MailResult = Result<MailAddrs, ParseHeaderFromError>;

// TODO rename!
#[derive(Debug, PartialEq, Eq)]
pub struct EmailAddr {
    pub local_part: String,
    pub domain: DomainName,
}

impl EmailAddr {
    pub fn new(addr: &str) -> Result<EmailAddr, Box<dyn std::error::Error>> {
        let (local_part, domain) = addr.rsplit_once('@').ok_or("not an email addr")?;

        let domain = DomainName::new(domain)?;
        Ok(Self {
            local_part: local_part.into(),
            domain,
        })
    }
}

impl Display for EmailAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local_part, self.domain.as_ref())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct MailAddrs(Vec<MailAddr>);  // non-empty

#[derive(Debug, PartialEq, Eq)]
pub struct MailAddr {
    local_part: String,
    domain_part: DomainPart,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DomainPart {
    Domain(String),
    DomainLiteral(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseHeaderFromError {
    // InvalidUtf8,  // get rid of this?
    // MultipleAddrs,
    DomainLiteral,
    Syntax,
    InvalidDomain,
}

// TODO clean up
// "From:" mailbox-list CRLF
//
// mailbox-list    =   (mailbox *("," mailbox))
// mailbox         =   name-addr / addr-spec
// name-addr       =   [display-name] angle-addr
// angle-addr      =   [CFWS] "<" addr-spec ">" [CFWS]
// display-name    =   phrase
//
// phrase          =   1*word
// word            =   atom / quoted-string
// atom            =   [CFWS] 1*atext [CFWS]
//
// addr-spec       =   local-part "@" domain
// local-part      =   dot-atom / quoted-string
// domain          =   dot-atom / domain-literal
// domain-literal  =   [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
// dtext           =   %d33-90 / %d94-126    ; Printable US-ASCII characters not including "[", "]", or "\"
//
// dot-atom        =   [CFWS] dot-atom-text [CFWS]
// dot-atom-text   =   1*atext *("." 1*atext)
//
// quoted-string   =   [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]

// work on bytes, and do lenient (but not insecure) parsing, allowing ill-formed
// but occasionally seen Latin1 et al in a header field value

pub fn parse_header_sender_address(input: &[u8]) -> Result<EmailAddr, ParseHeaderFromError> {
    let (mbox, rest) = parse_mailbox(input).ok_or(ParseHeaderFromError::Syntax)?;

    if !rest.is_empty() {
        return Err(ParseHeaderFromError::Syntax);
    }

    match mbox.domain_part {
        DomainPart::Domain(s) => {
            // validate domain name, see RFC 5322, §3.4.1
            let domain = DomainName::new(s).map_err(|_| ParseHeaderFromError::InvalidDomain)?;
            Ok(EmailAddr {
                local_part: mbox.local_part,
                domain,
            })
        }
        DomainPart::DomainLiteral(_) => Err(ParseHeaderFromError::DomainLiteral),
    }
}

pub fn parse_header_from_addresses(input: &[u8]) -> Result<Vec<EmailAddr>, ParseHeaderFromError> {
    let (mboxes, rest) = parse_mailboxes(input).ok_or(ParseHeaderFromError::Syntax)?;

    if !rest.is_empty() {
        return Err(ParseHeaderFromError::Syntax);
    }

    let mboxes = mboxes.0;

    // if mboxes.len() > 1 {
    //     return Err(ParseHeaderFromError::MultipleAddrs);
    // }

    mboxes.into_iter().map(|mbox| {
        match mbox.domain_part {
            DomainPart::Domain(s) => {
                // validate domain name, see RFC 5322, §3.4.1
                let domain = DomainName::new(s).map_err(|_| ParseHeaderFromError::InvalidDomain)?;
                Ok(EmailAddr {
                    local_part: mbox.local_part,
                    domain,
                })
            }
            // TODO allow domain literal when multiple addrs, b/c then not relevant!
            DomainPart::DomainLiteral(_) => Err(ParseHeaderFromError::DomainLiteral),
        }
    }).collect()
}

fn parse_mailboxes(input: &[u8]) -> Option<(MailAddrs, &[u8])> {
    let (mbox, mut rest) = parse_mailbox(input)?;
    let mut result = vec![mbox];
    while let Some((mbox, restx)) = rest.strip_prefix(b",").and_then(parse_mailbox) {
        result.push(mbox);
        rest = restx;
    }
    Some((MailAddrs(result), rest))
}

fn parse_mailbox(input: &[u8]) -> Option<(MailAddr, &[u8])> {
    let input = strip_cfws_if_any(input);

    let (addr, rest) =
        if let Some((addr, rest)) = parse_angle_addr(input).or_else(|| parse_addr_spec(input)) {
            (addr, rest)
        } else {
            // strip off display name: liberal interpretation: recognize
            // - cfws
            // - quoted-string
            // - except above two, mostly anything except "<" (begin of angle-addr)
            let f = |input| {
                strip_quoted_string(input)
                    .or_else(|| strip_display_name_content(input))
                    .map(strip_cfws_if_any)
            };
            let mut s = f(input)?;
            while let Some(snext) = f(s) {
                s = snext;
            }

            parse_angle_addr(s)?
        };

    let rest = strip_cfws_if_any(rest);

    Some((addr, rest))
}

fn strip_display_name_content(input: &[u8]) -> Option<&[u8]> {
    strip_many(input, |c| {
        c.is_ascii_graphic() && !matches!(c, b'<' | b'"' | b'(') || !c.is_ascii()
    })
}

fn parse_angle_addr(input: &[u8]) -> Option<(MailAddr, &[u8])> {
    let s = input.strip_prefix(b"<")?;

    let s = strip_cfws_if_any(s);

    let (addr, rest) = parse_addr_spec(s)?;

    let s = strip_cfws_if_any(rest);

    let rest = s.strip_prefix(b">")?;

    Some((addr, rest))
}

fn parse_addr_spec(input: &[u8]) -> Option<(MailAddr, &[u8])> {
    let to_string = |bytes| str::from_utf8(bytes).ok().map(|s| s.to_owned());

    let rest = strip_dot_atom(input).or_else(|| strip_quoted_string(input))?;
    let local_part = to_string(strip_suffix(input, rest))?;

    let s = strip_cfws_if_any(rest);

    let s = s.strip_prefix(b"@")?;

    let s = strip_cfws_if_any(s);

    let (domain_part, rest) = if let Some(rest) = strip_dot_atom(s) {
        let domain = to_string(strip_suffix(s, rest))?;
        (DomainPart::Domain(domain), rest)
    } else if let Some(rest) = strip_domain_literal(s) {
        let domain_literal = to_string(strip_suffix(s, rest))?;
        (DomainPart::DomainLiteral(domain_literal), rest)
    } else {
        return None;
    };

    let addr = MailAddr {
        local_part,
        domain_part,
    };

    Some((addr, rest))
}

fn strip_dot_atom(input: &[u8]) -> Option<&[u8]> {
    let mut s = strip_atext(input)?;
    while let Some(snext) = s.strip_prefix(b".").and_then(strip_atext) {
        s = snext;
    }
    Some(s)
}

fn strip_atext(input: &[u8]) -> Option<&[u8]> {
    // note: below does not contain @ . " , < > [ ] \
    strip_many(input, |c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'/'
                     | b'=' | b'?' | b'^' | b'_' | b'`' | b'{' | b'|' | b'}' | b'~'
            )
            || !c.is_ascii()
    })
}

// quoted-string = DQUOTE *([FWS] qcontent) [FWS] DQUOTE
// (Given our usage contexts, not including the surrounding CFWS, though.)
fn strip_quoted_string(input: &[u8]) -> Option<&[u8]> {
    // Note: Implementation is the same as `skip_comment` above.

    enum State { Content, Fws }

    let mut s = input.strip_prefix(b"\"")?;
    let mut state = State::Content;

    loop {
        match state {
            State::Content => {
                if let Some(snext) = s.strip_prefix(b"\"") {
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
                if let Some(snext) = s.strip_prefix(b"\"") {
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
fn strip_qcontent(input: &[u8]) -> Option<&[u8]> {
    strip_qtext(input).or_else(|| strip_quoted_pair(input))
}

fn strip_qtext(input: &[u8]) -> Option<&[u8]> {
    strip_many(input, |c| {
        c.is_ascii_graphic() && !matches!(c, b'"' | b'\\') || !c.is_ascii()
    })
}

fn strip_cfws_if_any(input: &[u8]) -> &[u8] {
    strip_cfws(input).unwrap_or(input)
}

// CFWS = (1*([FWS] comment) [FWS]) / FWS
pub fn strip_cfws(input: &[u8]) -> Option<&[u8]> {
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
                } else {
                    break;
                }
            }
        }
    }

    Some(s)
}

// FWS = ([*WSP CRLF] 1*WSP)
fn strip_fws(input: &[u8]) -> Option<&[u8]> {
    if let Some(s) = strip_wsp(input) {
        if let Some(s) = s.strip_prefix(CRLF) {
            strip_wsp(s)
        } else {
            Some(s)
        }
    } else {
        input.strip_prefix(CRLF).and_then(strip_wsp)
    }
}

fn strip_wsp(input: &[u8]) -> Option<&[u8]> {
    strip_many(input, is_wsp)
}

fn is_wsp(c: &u8) -> bool {
    matches!(c, b' ' | b'\t')
}

// comment = "(" *([FWS] ccontent) [FWS] ")"
fn strip_comment(input: &[u8]) -> Option<&[u8]> {
    enum State { Content, Fws }

    let mut s = input.strip_prefix(b"(")?;
    let mut state = State::Content;

    loop {
        match state {
            State::Content => {
                if let Some(snext) = s.strip_prefix(b")") {
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
                if let Some(snext) = s.strip_prefix(b")") {
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
fn strip_ccontent(input: &[u8]) -> Option<&[u8]> {
    strip_ctext(input)
        .or_else(|| strip_quoted_pair(input))
        .or_else(|| strip_comment(input))
}

fn strip_ctext(input: &[u8]) -> Option<&[u8]> {
    strip_many(input, is_ctext)
}

fn is_ctext(c: &u8) -> bool {
    c.is_ascii_graphic() && !matches!(c, b'(' | b')' | b'\\') || !c.is_ascii()
}

// "[" *([FWS] dtext) [FWS] "]"
fn strip_domain_literal(input: &[u8]) -> Option<&[u8]> {
    // Note: Implementation is the same as `skip_quoted_string` below.

    enum State { Content, Fws }

    let mut s = input.strip_prefix(b"[")?;
    let mut state = State::Content;

    loop {
        match state {
            State::Content => {
                if let Some(snext) = s.strip_prefix(b"]") {
                    s = snext;
                    break;
                } else if let Some(snext) = strip_dtext(s) {
                    s = snext;
                } else if let Some(snext) = strip_fws(s) {
                    s = snext;
                    state = State::Fws;
                } else {
                    return None;
                }
            }
            State::Fws => {
                if let Some(snext) = s.strip_prefix(b"]") {
                    s = snext;
                    break;
                } else if let Some(snext) = strip_dtext(s) {
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

fn strip_dtext(input: &[u8]) -> Option<&[u8]> {
    strip_many(input, |c| {
        c.is_ascii_graphic() && !matches!(c, b'[' | b'\\' | b']') || !c.is_ascii()
    })
}

fn strip_many(input: &[u8], pred: impl Fn(&u8) -> bool) -> Option<&[u8]> {
    let n = input.iter().take_while(|&c| pred(c)).count();
    if n > 0 {
        Some(&input[n..])
    } else {
        None
    }
}

// quoted-pair = ("\" (VCHAR / WSP))
fn strip_quoted_pair(input: &[u8]) -> Option<&[u8]> {
    let i = input.strip_prefix(b"\\")?;
    if matches!(i.first(), Some(c) if is_vchar(c) || is_wsp(c)) {
        Some(&i[1..])
    } else {
        None
    }
}

fn is_vchar(c: &u8) -> bool {
    // TODO no, this should consume an UTF-8 sequence if one is available! (?)
    c.is_ascii_graphic() || !c.is_ascii()
}

pub fn strip_suffix<'a>(s: &'a [u8], suffix: &[u8]) -> &'a [u8] {
    debug_assert!(s.ends_with(suffix));
    &s[..(s.len() - suffix.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header_from_addresses_ok() {
        assert_eq!(
            parse_header_from_addresses(b"  (all right:)\t \"let's see\" <does@this.work> "),
            Ok(vec![EmailAddr {
                local_part: "does".to_owned(),
                domain: DomainName::new("this.work").unwrap(),
            }])
        );
        assert_eq!(
            parse_header_from_addresses(b"  (all right:)\t \"let's see\" <does@this.1213121> "),
            Err(ParseHeaderFromError::InvalidDomain)
        );
    }

    #[test]
    fn parse_mailbox_ok() {
        assert_eq!(
            // display name contains "Rüedi" in Latin1 (= invalid UTF-8)
            parse_mailbox(b"  (\r\n hoi R\xfcedi (R\xc3\xbcedi in Latin1) )\t \"hei\" <ruedi@go> "),
            Some((
                MailAddr {
                    local_part: "ruedi".into(),
                    domain_part: DomainPart::Domain("go".into())
                },
                &b""[..]
            ))
        );
    }

    #[test]
    fn parse_angle_addr_ok() {
        assert_eq!(
            parse_angle_addr(b"<me@what.com>"),
            Some((
                MailAddr {
                    local_part: "me".into(),
                    domain_part: DomainPart::Domain("what.com".into())
                },
                &b""[..]
            ))
        );
        assert_eq!(
            parse_angle_addr(b"<me@[1.2\r\n\tx8-]>"),
            Some((
                MailAddr {
                    local_part: "me".into(),
                    domain_part: DomainPart::DomainLiteral("[1.2\r\n\tx8-]".into())
                },
                &b""[..]
            ))
        );
        assert_eq!(
            parse_angle_addr(b"<\"who \" @\twhat.->"),
            Some((
                MailAddr {
                    local_part: "\"who \"".into(),
                    domain_part: DomainPart::Domain("what.-".into())
                },
                &b""[..]
            ))
        );
    }
}
