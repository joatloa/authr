use actix_web::web::{self, ServiceConfig};

use crate::http::handlers;

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .service(handlers::sign_up)
            .service(handlers::sign_in)
            .service(handlers::sign_out)
            .service(handlers::session)
            .service(handlers::forgot_password)
            .service(handlers::reset_password)
            .service(handlers::provider)
            .service(handlers::provider_callback)
            .service(handlers::link_provider),
    );
}
