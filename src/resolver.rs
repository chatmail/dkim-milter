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

use crate::util::{self, BoxFuture};
use domain::{
    base::{iana::Rcode, Name, Rtype},
    rdata::Txt,
    resolv::{
        stub::conf::{ResolvConf, ResolvOptions},
        StubResolver,
    },
};
use std::{
    io::{self, ErrorKind},
    sync::Arc,
    time::Duration,
};
use viadkim::verifier::LookupTxt;

pub type LookupFuture<'a> = BoxFuture<'a, io::Result<Vec<io::Result<Vec<u8>>>>>;

#[derive(Clone)]
pub struct MockLookupTxt {
    mock_resolver: Arc<dyn Fn(&str) -> LookupFuture<'_> + Send + Sync>,
}

impl MockLookupTxt {
    pub fn new(mock_resolver: Arc<dyn Fn(&str) -> LookupFuture<'_> + Send + Sync>) -> Self {
        Self { mock_resolver }
    }
}

impl LookupTxt for MockLookupTxt {
    type Answer = Vec<io::Result<Vec<u8>>>;
    type Query<'a> = BoxFuture<'a, io::Result<Self::Answer>>;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
        let domain = domain.to_owned();
        Box::pin(async move { (self.mock_resolver)(&domain).await })
    }
}

pub enum Resolver {
    Live(DomainResolver),
    Mock(Arc<MockLookupTxt>),
}

#[derive(Clone)]
pub struct DomainResolver {
    resolver: Arc<StubResolver>,
}

impl DomainResolver {
    pub fn new(timeout: Duration) -> Self {
        let options = ResolvOptions {
            timeout,
            ..Default::default()
        };

        let mut conf = ResolvConf {
            options,
            ..Default::default()
        };

        conf.finalize();

        let resolver = Arc::new(StubResolver::from_conf(conf));

        Self { resolver }
    }
}

impl LookupTxt for DomainResolver {
    type Answer = Vec<io::Result<Vec<u8>>>;
    type Query<'a> = BoxFuture<'a, io::Result<Self::Answer>>;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
        let name = Name::vec_from_str(domain);

        Box::pin(async move {
            let name = name.map_err(|_| ErrorKind::InvalidInput)?;

            let answer = self.resolver.query((name, Rtype::TXT)).await?;

            if answer.is_error() {
                return Err(match answer.header().rcode() {
                    Rcode::NXDOMAIN => ErrorKind::NotFound.into(),
                    rcode => io::Error::other(rcode.to_string()),
                });
            }

            let results = answer
                .answer()
                .map_err(|_| ErrorKind::InvalidData)?
                .limit_to::<Txt<_>>()
                .map(|r| match r {
                    Ok(record) => {
                        let txt = record.into_data().text();
                        Ok(normalize_whitespace(txt))
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
fn normalize_whitespace(mut bytes: Vec<u8>) -> Vec<u8> {
    while let Some(b) = bytes.last() {
        if matches!(b, b' ' | b'\t') {
            bytes.pop();
        } else {
            break;
        }
    }

    util::normalize_to_crlf(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_whitespace_ok() {
        let record = b"v=1;\r\n\tw=2;\n\t;x=3; ".to_vec();
        assert_eq!(normalize_whitespace(record), b"v=1;\r\n\tw=2;\r\n\t;x=3;");
    }
}
