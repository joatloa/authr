use std::{collections::HashMap, net::SocketAddr};

use actix_web::HttpRequest;
use url::Url;

use crate::core::{error::AuthrError, oauth::Provider};

#[derive(Debug)]
/// How Authr determines the public host used in generated URLs and bind address.
pub enum BaseUrl {
    /// Uses a fixed URL for the Authr instance.
    Link { host: String },
    /// Allows Authr to operate across multiple domains.
    List {
        allowed_hosts: Vec<String>,
        fallback: String,
    },
}
impl BaseUrl {
    pub fn socket_addr(&self) -> std::io::Result<SocketAddr> {
        let url = match self {
            Self::Link { host } => host,
            Self::List { fallback, .. } => fallback,
        };

        let url = url::Url::parse(url).map_err(std::io::Error::other)?;

        let host = url
            .host_str()
            .ok_or_else(|| std::io::Error::other("Missing host"))?;

        let port = url
            .port_or_known_default()
            .ok_or_else(|| std::io::Error::other("Missing port"))?;

        format!("{host}:{port}")
            .parse()
            .map_err(std::io::Error::other)
    }
    pub fn resolve(&self, req: &HttpRequest) -> Result<Url, AuthrError> {
        match self {
            Self::Link { host } => Url::parse(host).map_err(|_| AuthrError::Internal),

            Self::List {
                allowed_hosts,
                fallback,
            } => {
                let connection = req.connection_info();
                let host = connection.host();

                let is_allowed = allowed_hosts
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(host));

                let base = if is_allowed {
                    format!("{}://{}", connection.scheme(), host)
                } else {
                    fallback.clone()
                };

                Url::parse(&base).map_err(|_| AuthrError::Internal)
            }
        }
    }
}
impl From<String> for BaseUrl {
    fn from(host: String) -> Self {
        Self::Link { host }
    }
}
impl From<&str> for BaseUrl {
    fn from(host: &str) -> Self {
        Self::Link {
            host: host.to_string(),
        }
    }
}

// -----
#[derive(Debug)]
/// Password authentication policy.
pub struct EmailAndPassword {
    /// Maximum number of characters allowed in a password.
    ///
    /// Defaults to `128`.
    pub max_password_length: usize,
    /// Minimum number of characters required in a password.
    ///
    /// Defaults to `8`.
    pub min_password_length: usize,
    /// Whether Authr should automatically create a session and sign in
    /// the user after a successful registration.
    ///
    /// Defaults to `true`.
    pub auto_sign_in: bool,
}
impl Default for EmailAndPassword {
    fn default() -> Self {
        Self {
            max_password_length: 128,
            min_password_length: 8,
            auto_sign_in: true,
        }
    }
}

// -----
#[derive(Debug)]
/// OAuth providers available for social sign-in, keyed by provider ID.
pub struct SocialProviders(HashMap<String, Provider>);

impl SocialProviders {
    pub fn new(providers: Vec<(String, Provider)>) -> SocialProviders {
        Self(providers.into_iter().collect())
    }
    pub fn get(&self, id: &str) -> Option<&Provider> {
        self.0.get(id)
    }
}

// -----
/// Configuration used to initialize an Authr instance.
#[derive(Debug)]
pub struct AuthrConfig {
    /// Display name of the application using Authr.
    ///
    /// Used in contexts where the application needs to be identified,
    /// such as the default issuer name displayed by authenticator apps
    /// during TOTP setup.
    pub app_name: String,
    /// Public URL configuration for the Authr instance.
    ///
    /// Used to construct authentication URLs, including OAuth callback
    /// URLs. Supports both static and multi-domain configurations.
    pub base_url: BaseUrl,
    /// Base path under which Authr's authentication routes are mounted.
    ///
    /// For example, `/api/auth` results in routes such as
    /// `/api/auth/sign-in/email` and `/api/auth/callback/google`.
    pub base_path: String,
    /// Connection URL used to establish a connection to the
    /// authentication database.
    pub database_url: String,
    /// This secret should be unique to your application, kept private,
    /// and provided through an environment variable or secret manager.
    ///
    /// Generate a secure secret using:
    ///
    /// ```bash
    /// openssl rand -base64 32
    /// ```
    ///
    /// Changing this secret may invalidate existing sessions or make
    /// previously encrypted data inaccessible.
    pub secret: String,
    /// Configuration for email and password authentication.
    pub email_and_password: EmailAndPassword,
    /// OAuth providers registered with Authr.
    pub social_providers: SocialProviders,
    /// Whether Authr should suppress its own tracing events.
    pub disable_logs: bool,
}
