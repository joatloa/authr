//! Authentication services for Rust applications using Actix Web.
//!
//! Authr is an authentication library that provides email/password and OAuth
//! authentication, session management, and a pluggable persistence layer.
//! It is designed to work both as a standalone authentication server and as
//! part of an existing Actix Web application.
//!
//! # Features
//!
//! - Email/password authentication.
//! - OAuth authentication with configurable providers.
//! - Session creation, retrieval, and management.
//! - Session middleware for protecting routes.
//! - Pluggable database storage with a built-in Diesel adapter.
//! - Configurable routing and individually accessible HTTP handlers.
//!
//! # Architecture
//!
//! The library is organized into three main modules:
//!
//! - [`core`] contains authentication configuration, shared types, context,
//!   cryptographic utilities, and OAuth provider abstractions.
//! - [`database`] defines the persistence contract and provides the Diesel
//!   database adapter, models, schema, and migrations.
//! - [`http`] exposes the Actix Web integration, including the router,
//!   request handlers, middleware, and HTTP utilities.
//!
//! # Running the authentication server
//!
//! The simplest way to use Authr is to let it configure and run its own
//! Actix Web server through [`run_authr`]. This is useful when you want to
//! deploy authentication as a separate service.
//!
//! ```ignore
//! use std::{env, error::Error};
//!
//! use authr::core::auth::{AuthrConfig, EmailAndPassword, SocialProviders, run_authr};
//! use dotenvy::dotenv;
//! use tracing_subscriber::EnvFilter;
//!
//! #[actix_web::main]
//! async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
//!     dotenv().ok();
//!
//!     // ----- Logging
//!     tracing_subscriber::fmt()
//!         .with_env_filter(
//!             EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
//!         )
//!         .init();
//!
//!     // ----- Configuration
//!     let config = AuthrConfig {
//!         app_name: "My Application".to_string(),
//!         base_url: "http://127.0.0.1:6767".into(),
//!         base_path: "/api/auth".to_string(),
//!         secret: env::var("SECRET").expect("SECRET must be set"),
//!         database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
//!         email_and_password: EmailAndPassword::default(),
//!         social_providers: SocialProviders::new(vec![]),
//!         disable_logs: false,
//!     };
//!
//!     // ----- Start Authr
//!     run_authr(config).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Integrating with an existing Actix Web application
//!
//! If you already have an Actix Web server, you can integrate Authr without
//! starting a separate server. Use [`http::router::config`] to register all
//! authentication routes under an Actix Web scope.
//!
//! ```ignore
//! use actix_web::{App, HttpServer, web};
//! use authr::core::auth::{AuthrConfig, AuthrContext};
//! use authr::database::adapter::DieselAdapter;
//! use authr::http::router;
//!
//! # async fn example(
//! #     database: DieselAdapter,
//! #     config: AuthrConfig,
//! # ) -> std::io::Result<()> {
//! let context = web::Data::new(AuthrContext::new(database, config));
//!
//! HttpServer::new(move || {
//!     App::new()
//!         .app_data(context.clone())
//!         .service(
//!             web::scope("/api/auth")
//!                 .configure(router::config::<DieselAdapter>),
//!         )
//! })
//! .bind(("127.0.0.1", 6767))?
//! .run()
//! .await
//! # }
//! ```
//!
//! # Using individual handlers
//!
//! Authr also exposes its HTTP handlers individually through [`http::handlers`].
//! This allows you to register only the endpoints you need, customize their
//! paths, or integrate them into a routing structure that differs from the
//! default Authr router.
//!
//! Each handler receives the shared [`AuthrContext`] through Actix Web's
//! application data, so make sure to register the context with `.app_data()`.
//!
//! ```ignore
//! use actix_web::{App, web};
//! use authr::core::auth::{AuthrConfig, AuthrContext};
//! use authr::database::adapter::DieselAdapter;
//! use authr::http::handlers;
//!
//! # fn example(database: DieselAdapter, config: AuthrConfig) {
//! let context = web::Data::new(AuthrContext::new(database, config));
//!
//! let app = App::new()
//!     .app_data(context)
//!     .route("/auth/register", web::post().to(handlers::sign_up::<DieselAdapter>))
//!     .route("/auth/login", web::post().to(handlers::sign_in_email::<DieselAdapter>))
//!     .route("/auth/logout", web::post().to(handlers::sign_out::<DieselAdapter>))
//!     .route("/auth/session", web::get().to(handlers::get_session::<DieselAdapter>));
//! # }
//! ```
//!
//! # Logging
//!
//! Authr uses the `tracing` ecosystem for structured application logging.
//!
//! The application is responsible for initializing a global tracing
//! subscriber. For example, `tracing_subscriber` can be used to configure
//! log formatting and filtering through the `RUST_LOG` environment variable.
//!
//! The `disable_logs` configuration option can be used to disable Authr's
//! internal logging. It does not initialize or configure the application's
//! tracing subscriber, and does not affect logging performed by other parts
//! of the application.

pub mod core;
pub mod database;
pub mod http;
