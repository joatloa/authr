use actix_web::{
    middleware::from_fn,
    web::{self, ServiceConfig},
};

use crate::{
    database::store::AuthDatabase,
    http::{handlers, middleware::session::require_session},
};

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
        .route("/sign-out", web::post().to(handlers::sign_out::<D>))
        // ----- Session
        .route("/get-session", web::get().to(handlers::get_session::<D>))
        // Protected
        .service(
            web::scope("")
                .wrap(from_fn(require_session::<D, _>))
                .route(
                    "/list-sessions",
                    web::get().to(handlers::list_sessions::<D>),
                )
                .route(
                    "/revoke-session",
                    web::post().to(handlers::revoke_session::<D>),
                )
                .route(
                    "/revoke-sessions",
                    web::post().to(handlers::revoke_sessions::<D>),
                )
                .route(
                    "/revoke-other-sessions",
                    web::post().to(handlers::revoke_other_sessions::<D>),
                ),
        );
}
