use std::sync::Arc;

use crate::{
    core::{
        auth::{AuthrConfig, store::AuthrStore},
        error::AuthrError,
        secrets::{AuthrSecrets, derive_secrets},
        utils::create_argon,
    },
    database::store::AuthDatabase,
};
use actix_web::web;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use email_address::EmailAddress;
use rand::rngs::OsRng;

/// Shared authentication state provided to Authr request handlers.
pub struct AuthrContext<D: AuthDatabase + 'static> {
    config: AuthrConfig,

    store: AuthrStore<D>,

    argon: Argon2<'static>,
    secrets: Arc<AuthrSecrets>,
}

impl<D: AuthDatabase + 'static> AuthrContext<D> {
    /// Creates a context from a database implementation and configuration.
    pub fn new(database: D, config: AuthrConfig) -> Self {
        let secrets = Arc::new(derive_secrets(&config.secret));
        let store = AuthrStore::new(database, secrets.clone());
        let argon = create_argon();

        Self {
            store,
            config,
            argon,
            secrets,
        }
    }
    /// Returns the convenience persistence facade.
    pub fn store(&self) -> &AuthrStore<D> {
        &self.store
    }
    /// Returns the active Authr configuration.
    pub fn config(&self) -> &AuthrConfig {
        &self.config
    }
    /// Returns the configured Argon2 password hasher.
    pub fn argon(&self) -> &Argon2<'static> {
        &self.argon
    }
    /// Returns the secrets
    pub fn secrets(&self) -> &AuthrSecrets {
        &self.secrets
    }

    // -------------------- Helper Methods --------------------

    // ----- Validation
    pub fn is_email_valid(&self, email: &str) -> bool {
        EmailAddress::is_valid(email)
    }
    pub fn is_password_vaild(&self, password: &str) -> bool {
        password.len() >= self.config.email_and_password.min_password_length
            && password.len() <= self.config.email_and_password.max_password_length
    }
    pub fn is_name_valid(&self, name: &str) -> bool {
        !name.trim().is_empty()
    }

    // ----- Password - Hash/Verify
    pub async fn hash_password(&self, password: String) -> Result<String, AuthrError> {
        let argon = self.argon.clone();

        web::block(move || {
            let salt = SaltString::generate(&mut OsRng);

            let password_hash = argon
                .hash_password(password.as_bytes(), &salt)
                .map_err(|_| AuthrError::PasswordHashingFailed)?
                .to_string();

            Ok(password_hash)
        })
        .await
        .map_err(|_| AuthrError::PasswordHashingFailed)?
    }
    pub async fn verify_password(
        &self,
        password: String,
        hash: String,
    ) -> Result<bool, AuthrError> {
        web::block(move || {
            let parsed_hash =
                PasswordHash::new(&hash).map_err(|_| AuthrError::PasswordVerificationFailed)?;

            Ok(Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok())
        })
        .await
        .map_err(|_| AuthrError::PasswordVerificationFailed)?
    }
}
