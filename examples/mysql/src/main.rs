use std::{env, error::Error};

use authr::core::auth::{AuthrConfig, EmailAndPassword, SocialProviders, run_authr};
use dotenvy::dotenv;
use tracing_subscriber::EnvFilter;

#[actix_web::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    dotenv().ok();

    // ----- Tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // ----- Configuration
    let config = AuthrConfig {
        app_name: "Mysql Test".to_string(),
        base_url: "http://127.0.0.1:6767".into(),
        base_path: "/api/auth".to_string(),
        secret: env::var("SECRET").expect("error: SECRET must be set"),
        database_url: env::var("DATABASE_URL").expect("error: DATABASE_URL must be set"),
        email_and_password: EmailAndPassword::default(),
        social_providers: SocialProviders::new(vec![]),
        disable_logs: false,
    };

    // ----- Start Authr
    run_authr(config).await?;

    Ok(())
}
