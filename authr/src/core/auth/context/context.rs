use std::sync::Arc;

use crate::{
    core::{
        auth::{AuthrConfig, context::store::AuthrStore},
        secrets::{AuthrSecrets, derive_secrets},
        utils::create_argon,
    },
    database::store::AuthDatabase,
};
use argon2::Argon2;

/// Shared authentication state provided to Authr request handlers.
pub struct AuthrContext<D: AuthDatabase + 'static> {
    store: AuthrStore<D>,
    config: AuthrConfig,
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
}
