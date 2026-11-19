use actix_web::{App, HttpServer, web};

use crate::{
    core::{
        auth::{AuthrConfig, AuthrData},
        utils::create_argon,
    },
    database::adapter::DieselDatabase,
    http::router,
};

pub async fn run_authr(config: AuthrConfig) -> std::io::Result<()> {
    let database = DieselDatabase::from_url(&config.database_url).map_err(std::io::Error::other)?;

    let addr = config.base_url.socket_addr()?;

    let data = web::Data::new(AuthrData {
        database,
        config,
        argon: create_argon(),
    });

    HttpServer::new(move || App::new().app_data(data.clone()).configure(router::config))
        .bind(addr)?
        .run()
        .await
}
