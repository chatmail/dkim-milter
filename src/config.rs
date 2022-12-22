use crate::crypto::CachedKeyStore;
use std::{collections::HashMap, path::PathBuf};
use viadkim::signer::KeyId;

// TODO provisional
pub struct Config {
    pub keys_path_to_id: HashMap<PathBuf, KeyId>,
    pub keys_id_to_key: CachedKeyStore,

    // only two keys for now, later arbitrary key selection
    pub rsa_key_path: PathBuf,
    pub ed25519_key_path: PathBuf,

    pub authserv_id: String,
    pub domain_to_sign: String,
}
