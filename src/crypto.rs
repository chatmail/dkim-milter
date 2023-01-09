use std::{collections::HashMap, future::Future, io, pin::Pin, sync::Arc};
use viadkim::{
    crypto::{KeyType, SigningKey},
    signer::{KeyId, KeyStore},
};

#[derive(Default)]
pub struct CachedKeyStore {
    map: HashMap<KeyId, Arc<SigningKey>>,
}

impl CachedKeyStore {
    pub fn new(map: HashMap<KeyId, Arc<SigningKey>>) -> Self {
        Self { map }
    }

    pub fn get_key_type(&self, key_id: KeyId) -> Option<KeyType> {
        self.map.get(&key_id).map(|k| k.to_key_type())
    }
}

impl KeyStore for CachedKeyStore {
    type Query<'a> =
        Pin<Box<dyn Future<Output = Result<Option<Arc<SigningKey>>, io::Error>> + Send + 'a>>;

    fn get(&self, key_id: KeyId) -> Self::Query<'_> {
        Box::pin(async move {
            let signing_key = match self.map.get(&key_id) {
                Some(k) => k,
                None => return Ok(None),
            };

            let signing_key = signing_key.clone();

            Ok(Some(signing_key))
        })
    }
}
