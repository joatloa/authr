use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

pub fn generate_random_value() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);

    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn hash_str(str: &str) -> String {
    let hash = Sha256::digest(str.as_bytes());

    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}
