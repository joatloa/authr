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
        // -------------------- Email/Password Flow --------------------
        .route("/sign-up", web::post().to(handlers::sign_up::<D>))
        .route(
            "/sign-in/email",
            web::post().to(handlers::sign_in_email::<D>),
        )
        // -------------------- OAuth2 Flow --------------------
        .route(
            "/sign-in/social",
            web::post().to(handlers::sign_in_social::<D>),
        )
        .route(
            "/callback/{provider}",
            web::get().to(handlers::callback::<D>),
        )
        // -------------------- Sign Out --------------------
        .route("/sign-out", web::post().to(handlers::sign_out::<D>))
        // -------------------- Password --------------------
        .route(
            "/request-password-reset",
            web::post().to(handlers::request_password_reset::<D>),
        )
        .route(
            "/reset-password/{token}",
            web::get().to(handlers::reset_password_callback::<D>),
        )
        .route(
            "/reset-password",
            web::post().to(handlers::reset_password::<D>),
        )
        // Keep this public route ahead of the empty-prefix protected scope.
        .route("/get-session", web::get().to(handlers::get_session::<D>))
        // Protected
        .service(
            web::scope("")
                .wrap(from_fn(require_session::<D, _>))
                .route(
                    "/verify-password",
                    web::post().to(handlers::verify_password::<D>),
                )
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
