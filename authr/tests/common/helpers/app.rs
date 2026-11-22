use authr::core::auth::{AuthrConfig, BaseUrl, EmailAndPassword, SocialProviders};

pub(crate) fn config(auto_sign_in: bool, social_providers: SocialProviders) -> AuthrConfig {
    AuthrConfig {
        app_name: "Authr Tests".to_string(),
        base_url: BaseUrl::from("http://localhost:3000"),
        base_path: "/api/auth".to_string(),
        database_url: String::new(),
        secret: super::super::TEST_SECRET.to_string(),
        email_and_password: EmailAndPassword {
            auto_sign_in,
            ..Default::default()
        },
        social_providers,
        disable_logs: false,
    }
}

// -----

pub(crate) fn config_with(
    auto_sign_in: bool,
    social_providers: SocialProviders,
    configure: impl FnOnce(&mut AuthrConfig),
) -> AuthrConfig {
    let mut auth_config = config(auto_sign_in, social_providers);
    configure(&mut auth_config);
    auth_config
}

// -----

macro_rules! test_app {
    ($database:expr) => {
        $crate::common::helpers::test_app!(
            $database,
            $crate::common::helpers::config(true, authr::core::auth::SocialProviders::new(vec![]))
        )
    };
    ($database:expr, $config:expr) => {{
        let data = actix_web::web::Data::new(authr::core::auth::AuthrContext::new(
            $database.clone(),
            $config,
        ));

        actix_web::test::init_service(
            actix_web::App::new().app_data(data).service(
                actix_web::web::scope("/api/auth")
                    .configure(authr::http::router::config::<$crate::common::mock::TestDatabase>),
            ),
        )
        .await
    }};
}
pub(crate) use test_app;
