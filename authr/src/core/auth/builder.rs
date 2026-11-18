use std::net::SocketAddr;

#[cfg(feature = "mysql")]
use crate::database::adapters::MysqlDatabase;

use crate::core::{error::AuthrError, oauth::Provider};

#[derive(Default)]
pub struct Authr {
    pub(crate) address: Option<SocketAddr>,

    #[cfg(feature = "mysql")]
    pub(crate) database: Option<MysqlDatabase>,
    pub(crate) base_url: Option<String>,
    pub(crate) providers: Vec<Provider>,
}

impl Authr {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn address(&mut self, addrs: SocketAddr) -> &mut Self {
        self.address = Some(addrs);

        self
    }
    pub fn database(&mut self, database_url: &str) -> Result<&mut Self, AuthrError> {
        #[cfg(feature = "mysql")]
        let database = MysqlDatabase::from_url(database_url)?;

        self.database = Some(database);

        Ok(self)
    }
    pub fn providers(&mut self, providers: Vec<Provider>) -> &mut Self {
        self.providers = providers;
        self
    }
    pub fn base_url(&mut self, base_url: String) -> &mut Self {
        self.base_url = Some(base_url);
        self
    }
}
