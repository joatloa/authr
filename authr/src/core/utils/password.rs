use actix_web::web;
use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use rand::rngs::OsRng;

use crate::core::error::AuthrError;

// ----- Password
pub fn create_argon() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, None).expect("Invalid Argon2 parameters");

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(argon2: &Argon2<'static>, password: &str) -> Result<String, AuthrError> {
    let salt = SaltString::generate(&mut OsRng);

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AuthrError::PasswordHashingFailed)?
        .to_string();

    Ok(password_hash)
}
pub async fn hash_password_async(
    argon: Argon2<'static>,
    password: String,
) -> Result<String, AuthrError> {
    web::block(move || hash_password(&argon, &password))
        .await
        .map_err(|_| AuthrError::PasswordHashingFailed)?
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthrError> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|_| AuthrError::PasswordVerificationFailed)?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
pub async fn verify_password_async(password: String, hash: String) -> Result<bool, AuthrError> {
    web::block(move || verify_password(&password, &hash))
        .await
        .map_err(|_| AuthrError::PasswordVerificationFailed)?
}
