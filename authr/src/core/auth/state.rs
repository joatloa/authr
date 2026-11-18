use std::collections::HashMap;

use argon2::Argon2;

use crate::core::oauth::Provider;
#[cfg(feature = "mysql")]
use crate::database::adapters::MysqlDatabase;

pub struct ProviderRegistry(pub HashMap<String, Provider>);

impl ProviderRegistry {
    pub fn get(&self, id: &str) -> Option<&Provider> {
        self.0.get(id)
    }
}

pub struct AuthrData {
    pub base_url: String,
    pub providers: ProviderRegistry,

    #[cfg(feature = "mysql")]
    pub database: MysqlDatabase,

    pub argon: Argon2<'static>,
}
