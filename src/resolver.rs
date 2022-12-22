use bytes::Bytes;
use domain::{
    base::{
        message::RecordIter, name::ParsedDname, octets::ParseError, record::Record, Dname,
        RecordSection, Rtype,
    },
    rdata::Txt,
    resolv::StubResolver,
};
use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
    str::FromStr,
    sync::Arc,
};
use viadkim::verifier::LookupTxt;

#[derive(Clone)]
pub struct Resolver {
    pub resolver: Arc<StubResolver>,
}

impl Resolver {
    pub fn new() -> Self {
        let resolver = Arc::new(StubResolver::new());

        Self { resolver }
    }

    async fn lookup_txt_internal(
        &self,
        name: Dname<Vec<u8>>,
    ) -> Result<Vec<Result<Vec<u8>, io::Error>>, io::Error> {
        // TODO this is a building site, infer types etc.

        let answer = self.resolver.query((name, Rtype::Txt)).await?;
        let record_section: RecordSection<&Bytes> = answer
            .answer()
            .map_err(|_| io::Error::from(ErrorKind::InvalidData))?;
        let record_iter: RecordIter<&Bytes, Txt<Bytes>> = record_section.limit_to::<Txt<Bytes>>();
        let results: Vec<_> = record_iter
            .map(
                |res: Result<Record<ParsedDname<&Bytes>, Txt<Bytes>>, ParseError>| match res {
                    Ok(record) => {
                        let txt: Txt<Bytes> = record.into_data();
                        Ok(txt.text::<Vec<u8>>().unwrap())
                    }
                    Err(_e) => Err(io::Error::from(ErrorKind::InvalidData)),
                },
            )
            .collect();
        Ok(results)
    }
}

impl LookupTxt for Resolver {
    type Answer = Vec<Result<Vec<u8>, io::Error>>;
    type Query<'a> = Pin<Box<dyn Future<Output = Result<Self::Answer, io::Error>> + Send + 'a>>;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
        let result = Dname::from_str(domain);
        Box::pin(async move {
            let dname = result.map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
            self.lookup_txt_internal(dname).await
        })
    }
}
