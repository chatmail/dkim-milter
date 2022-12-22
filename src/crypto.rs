use std::{
    collections::HashMap,
    future::Future,
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};
use tokio::fs;
use viadkim::{
    crypto::{self, KeyType, SigningKey},
    signer::{KeyId, KeyStore},
};

// TODO only two keys for now, later arbitrary
pub async fn make_key_store(
    rsa_key_path: impl AsRef<Path>,
    ed25519_key_path: impl AsRef<Path>,
) -> io::Result<(HashMap<PathBuf, KeyId>, CachedKeyStore)> {
    let rsa_key_path = rsa_key_path.as_ref();
    let ed25519_key_path = ed25519_key_path.as_ref();

    let rsa_key = get_signing_key_from_file(KeyType::Rsa, rsa_key_path).await?;
    let ed25519_key = get_signing_key_from_file(KeyType::Ed25519, ed25519_key_path).await?;

    let keys_path_to_id = HashMap::from([
        (rsa_key_path.into(), KeyId::new(0)),
        (ed25519_key_path.into(), KeyId::new(1)),
    ]);

    let keys_id_to_key = CachedKeyStore::new(HashMap::from([
        (KeyId::new(0), Arc::new(rsa_key)),
        (KeyId::new(1), Arc::new(ed25519_key)),
    ]));

    Ok((keys_path_to_id, keys_id_to_key))
}

async fn get_signing_key_from_file(
    key_type: KeyType,
    path: impl AsRef<Path>,
) -> io::Result<SigningKey> {
    let s = fs::read_to_string(path.as_ref()).await?;

    // TODO actually don't need key type, pkcs8 contains key type info
    match key_type {
        KeyType::Rsa => {
            let k = crypto::read_rsa_private_key(&s)?;
            Ok(SigningKey::Rsa(k))
        }
        KeyType::Ed25519 => {
            let k = crypto::read_ed25519_private_key(&s)?;
            Ok(SigningKey::Ed25519(k))
        }
    }
}

pub struct CachedKeyStore {
    map: HashMap<KeyId, Arc<SigningKey>>,
}

impl CachedKeyStore {
    pub fn new(map: HashMap<KeyId, Arc<SigningKey>>) -> Self {
        Self { map }
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
