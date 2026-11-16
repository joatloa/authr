use crate::http::router::config;
use actix_web::{App, HttpServer};

#[derive(Debug)]
pub struct Address {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Default)]
pub struct Authr {
    address: Option<Address>,
}

impl Authr {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn address(&mut self, addresss: Address) -> &mut Self {
        self.address = Some(addresss);

        self
    }
    pub async fn run(self) -> std::io::Result<()> {
        let Some(Address { host, port }) = self.address else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Server address is missing.",
            ));
        };

        HttpServer::new(|| App::new().app_data(()).configure(config))
            .bind((host, port))?
            .run()
            .await
    }
}
