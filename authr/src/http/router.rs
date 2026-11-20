use actix_web::web::{self, ServiceConfig};

use crate::{database::store::AuthDatabase, http::handlers};

pub fn config<D: AuthDatabase + 'static>(cfg: &mut ServiceConfig) {
    cfg
        // ----- Email/Password
        .route("/sign-up", web::post().to(handlers::sign_up::<D>))
        .route(
            "/sign-in/email",
            web::post().to(handlers::sign_in_email::<D>),
        )
        // ----- OAuth2
        .route(
            "/sign-in/social",
            web::post().to(handlers::sign_in_social::<D>),
        )
        .route(
            "/callback/{provider}",
            web::get().to(handlers::callback::<D>),
        )
        // ----- Other
        .route("/sign-out", web::post().to(handlers::sign_out::<D>));
}
