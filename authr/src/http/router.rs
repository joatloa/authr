use actix_web::web::{self, ServiceConfig};

use crate::http::handlers;

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            // ----- Email/Password
            .service(handlers::sign_up)
            .service(handlers::sign_in_email)
            // ----- Oauth2
            .service(handlers::sign_in_social)
            .service(handlers::callback)
            // ----- Other
            .service(handlers::sign_out),
    );
}
