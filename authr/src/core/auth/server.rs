use actix_web::{App, HttpServer, web};

use crate::{
    core::{
        builder::Authr,
        oauth::OAuthProvider,
        state::{AuthrData, ProviderRegistry},
    },
    http::router::config,
    utilities::password::create_argon,
};

impl Authr {
    pub async fn run(self) -> std::io::Result<()> {
        let Some(addrs) = self.address else {
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

        let Some(base_url) = self.base_url else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Base url is missing.",
            ));
        };

        let data = web::Data::new(AuthrData {
            database,
            base_url,
            providers: ProviderRegistry(
                self.providers
                    .into_iter()
                    .map(|p| (p.id().to_owned(), p))
                    .collect(),
            ),
            argon: create_argon(),
        });

        HttpServer::new(move || App::new().app_data(data.clone()).configure(config))
            .bind(addrs)?
            .run()
            .await
    }
}
