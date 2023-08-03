use bstr::ByteSlice;
use domain::{
    base::{iana::Rcode, Dname, Rtype},
    rdata::Txt,
    resolv::StubResolver,
};
use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
    sync::Arc,
};
use viadkim::verifier::LookupTxt;

#[derive(Clone)]
pub struct MockLookupTxt {
    pub mock_resolver: Arc<dyn Fn(&str) -> LookupFuture + Send + Sync>,
}

impl LookupTxt for MockLookupTxt {
    type Answer = Vec<io::Result<Vec<u8>>>;
    type Query<'a> = Pin<Box<dyn Future<Output = io::Result<Self::Answer>> + Send + 'a>>;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
        let domain = domain.to_owned();
        Box::pin(async move { (self.mock_resolver)(&domain).await })
    }
}

pub type LookupFuture = Pin<Box<dyn Future<Output = io::Result<Vec<io::Result<Vec<u8>>>>> + Send>>;

pub enum Resolver {
    Live(DomainResolver),
    Mock(Arc<MockLookupTxt>),
}

#[derive(Clone)]
pub struct DomainResolver {
    pub resolver: Arc<StubResolver>,
}

impl DomainResolver {
    pub fn new() -> Self {
        let resolver = Arc::new(StubResolver::new());

        Self { resolver }
    }
}

impl LookupTxt for DomainResolver {
    type Answer = Vec<io::Result<Vec<u8>>>;
    type Query<'a> = Pin<Box<dyn Future<Output = io::Result<Self::Answer>> + Send + 'a>>;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
        let dname = Dname::vec_from_str(domain);

        Box::pin(async move {
            let dname = dname.map_err(|_| ErrorKind::InvalidInput)?;

            let answer = self.resolver.query((dname, Rtype::Txt)).await?;

            if answer.is_error() {
                return Err(match answer.header().rcode() {
                    Rcode::NXDomain => ErrorKind::NotFound.into(),
                    rcode => io::Error::new(ErrorKind::Other, rcode.to_string()),
                });
            }

            let results = answer
                .answer()
                .map_err(|_| ErrorKind::InvalidData)?
                .limit_to::<Txt<_>>()
                .map(|r| match r {
                    Ok(record) => {
                        let txt = record.into_data().text();
                        Ok(normalize_line_breaks(txt))
                    }
                    Err(_) => Err(ErrorKind::InvalidData.into()),
                })
                .collect();

            Ok(results)
        })
    }
}

// There are key records that mistakenly use LF + WSP as line breaks, seen for
// example at mail._domainkey.circleshop.ch. Be nice and normalise to valid
// CRLF + WSP. Also trim trailing WSP, which is not allowed after semicolon.
fn normalize_line_breaks(mut bytes: Vec<u8>) -> Vec<u8> {
    while let Some(b) = bytes.last() {
        if matches!(b, b' ' | b'\t') {
            bytes.pop();
        } else {
            break;
        }
    }

    bstr::join(
        "\r\n",
        bytes.split_str("\r\n").flat_map(|b| b.split_str("\n")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_line_breaks_ok() {
        let record = b"v=1;\r\n\tw=2;\n\t;x=3; ".to_vec();
        assert_eq!(normalize_line_breaks(record), b"v=1;\r\n\tw=2;\r\n\t;x=3;");
    }
}
