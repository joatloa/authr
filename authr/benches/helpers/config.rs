#![allow(unused)]

use authr::core::auth::{AuthrConfig, BaseUrl, EmailAndPassword, SocialProviders};

pub const BENCH_SECRET: &str = "authr-benchmark-secret-that-is-long-enough-for-testing";

pub fn config(database_url: String) -> AuthrConfig {
    AuthrConfig {
        app_name: "Authr Benchmarks".into(),
        base_url: BaseUrl::from("http://localhost:8080"),
        base_path: "/api/auth".into(),
        database_url,
        secret: BENCH_SECRET.into(),
        email_and_password: EmailAndPassword::default(),
        social_providers: SocialProviders::new(vec![]),
        disable_logs: true,
    }
}
