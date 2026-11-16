use std::sync::Arc;

#[cfg(feature = "mysql")]
use crate::database::adapters::MysqlDatabase;
use crate::{database::store::AuthDatabase, http::router::config};
use actix_web::{App, HttpServer, web};

#[derive(Debug)]
pub struct Address {
    pub host: String,
    pub port: u16,
}

#[derive(Default)]
pub struct Authr {
    address: Option<Address>,
    database: Option<Arc<dyn AuthDatabase>>,
}

impl Authr {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn address(&mut self, addresss: Address) -> &mut Self {
        self.address = Some(addresss);

        self
    }
    pub fn database(
        &mut self,
        database_url: &str,
    ) -> Result<&mut Self, Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(feature = "mysql")]
        let database = MysqlDatabase::from_url(database_url)?;

        self.database = Some(Arc::new(database));

        Ok(self)
    }
    pub async fn run(self) -> std::io::Result<()> {
        let Some(Address { host, port }) = self.address else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Server address is missing.",
            ));
        };

        let Some(database) = self.database else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Database is missing.",
            ));
        };

        let data = web::Data::from(database);

        HttpServer::new(move || App::new().app_data(data.clone()).configure(config))
            .bind((host, port))?
            .run()
            .await
    }
}
