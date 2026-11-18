use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

// ----- Tokens
pub fn generate_random_value() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);

    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn hash_str(str: &str) -> String {
    let hash = Sha256::digest(str.as_bytes());

    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ----- Password
pub fn create_argon() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, None).expect("Invalid Argon2 parameters");

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}
pub fn hash_password(
    argon2: &Argon2<'static>,
    password: &str,
) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    Ok(password_hash)
}
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
