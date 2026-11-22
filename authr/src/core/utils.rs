use argon2::{Algorithm, Argon2, Params, Version};
use rand::{RngCore, rngs::OsRng};

/// Creates an Argon2id instance configured for password hashing.
pub fn create_argon() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, None).expect("Invalid Argon2 parameters");

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Generates a cryptographically secure random token. (64-character hexadecimal string)
pub fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);

    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
