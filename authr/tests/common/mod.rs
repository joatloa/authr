mod db;
mod log;
mod provider;

pub use db::TestDatabase;
pub use log::init_tracing;
pub use provider::MockOAuthProvider;

// ---- helpers
use authr::core::auth::{AuthrConfig, BaseUrl, EmailAndPassword, SocialProviders};

pub fn config(auto_sign_in: bool, social_providers: SocialProviders) -> AuthrConfig {
    AuthrConfig {
        app_name: "Authr Tests".to_string(),
        base_url: BaseUrl::from("http://localhost:3000"),
        base_path: "/api/auth".to_string(),
        database_url: String::new(),
        secret: "test-secret-that-is-long-enough-for-testing".to_string(),
        email_and_password: EmailAndPassword {
            auto_sign_in,
            ..Default::default()
        },
        social_providers,
        disable_logs: false,
    }
}

macro_rules! test_app {
    ($database:expr) => {
        test_app!($database, config(true, SocialProviders::new(vec![])))
    };
    ($database:expr, $config:expr) => {{
        let data = web::Data::new(AuthrContext::new($database.clone(), $config));

        test::init_service(
            App::new()
                .app_data(data)
                .service(web::scope("/api/auth").configure(router::config::<TestDatabase>)),
        )
        .await
    }};
}
pub(crate) use test_app;

macro_rules! sign_up_user {
    ($app:expr, $user:expr) => {{
        let request = test::TestRequest::post()
            .uri("/api/auth/sign-up")
            .set_json($user)
            .to_request();

        test::call_service(&$app, request).await
    }};
}
pub(crate) use sign_up_user;

macro_rules! sign_in_social {
    ($app:expr, $body:expr) => {{
        let request = test::TestRequest::post()
            .uri("/api/auth/sign-in/social")
            .set_json($body)
            .to_request();

        test::call_service(&$app, request).await
    }};
}

pub(crate) use sign_in_social;
