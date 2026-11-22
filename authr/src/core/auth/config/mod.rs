mod base_url;
mod email_and_password;
mod social_providers;

pub use base_url::*;
pub use email_and_password::*;
pub use social_providers::*;

/// Configuration used to initialize an Authr instance.
#[derive(Debug, Clone)]
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
