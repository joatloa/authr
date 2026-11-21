use crate::{
    core::{
        auth::{AuthrConfig, context::store::AuthrStore},
        utils::create_argon,
    },
    database::store::AuthDatabase,
};
use argon2::Argon2;

pub struct AuthrContext<D: AuthDatabase + 'static> {
    store: AuthrStore<D>,
    config: AuthrConfig,
    argon: Argon2<'static>,
}

impl<D: AuthDatabase + 'static> AuthrContext<D> {
    pub fn new(database: D, config: AuthrConfig) -> Self {
        Self {
            store: AuthrStore::new(database),
            config,
            argon: create_argon(),
        }
    }
    pub fn store(&self) -> &AuthrStore<D> {
        &self.store
    }
    pub fn config(&self) -> &AuthrConfig {
        &self.config
    }
    pub fn argon(&self) -> &Argon2<'static> {
        &self.argon
    }
}
