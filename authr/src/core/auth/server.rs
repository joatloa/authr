use actix_web::{App, HttpServer, web};

use crate::{
    core::auth::{AuthrConfig, AuthrContext},
    database::store::AuthDatabase,
    http::router,
};

// ----- Diesel
#[cfg(any(feature = "mysql", feature = "postgres", feature = "sqlite"))]
use crate::database::adapter::DieselDatabase;

#[cfg(any(feature = "mysql", feature = "postgres", feature = "sqlite"))]
pub async fn run_authr(config: AuthrConfig) -> std::io::Result<()> {
    let database = DieselDatabase::from_url(&config.database_url).map_err(std::io::Error::other)?;

    run_authr_impl(config, database).await
}

// ----- Custom store
#[cfg(not(any(feature = "mysql", feature = "postgres", feature = "sqlite")))]
pub async fn run_authr<D: AuthDatabase + 'static>(
    config: AuthrConfig,
    database: D,
) -> std::io::Result<()> {
    run_authr_impl(config, database).await
}

// ----- Server
async fn run_authr_impl<D: AuthDatabase + 'static>(
    config: AuthrConfig,
    database: D,
) -> std::io::Result<()> {
    let addr = config.base_url.socket_addr()?;

    let base_path = config.base_path.clone();

    let data = web::Data::new(AuthrContext::new(database, config));

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .service(web::scope(&base_path).configure(router::config::<D>))
    })
    .bind(addr)?
    .run()
    .await
}
