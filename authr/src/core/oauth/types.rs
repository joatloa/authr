use reqwest::Url;
use serde::{Deserialize, Serialize};

/// Inputs used to construct a provider authorization URL.
pub struct AuthorizationParams {
    /// Random OAuth state used to bind the callback to this login attempt.
    pub state: String,
    /// PKCE S256 challenge derived from the transaction verifier.
    pub code_challenge: String,
    /// Authr callback URL registered with the provider.
    pub redirect_uri: Url,
    /// Requested OAuth scopes.
    pub scopes: Vec<String>,
}

/// Inputs for exchanging an OAuth authorization code for tokens.
pub struct TokenExchangeParams {
    /// Authorization code received from the provider.
    pub code: String,
    /// Secret paired with the authorization request's PKCE challenge.
    pub code_verifier: String,
    /// Must match the redirect URI used to start authorization.
    pub redirect_uri: Url,
}

/// OAuth tokens returned by a provider.
pub struct TokenResponse {
    /// Access token for provider API requests.
    pub access_token: String,
    /// Optional refresh token.
    pub refresh_token: Option<String>,
    /// Optional OpenID Connect ID token.
    pub id_token: Option<String>,
    /// Access-token lifetime in seconds, when supplied.
    pub expires_in: Option<u64>,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Provider token type, commonly `Bearer`.
    pub token_type: Option<String>,
}

/// Normalized identity returned by an OAuth provider.
pub struct ProviderUser {
    /// Stable account identifier assigned by the provider.
    pub id: String,
    /// Optional display name.
    pub name: Option<String>,
    /// Optional email address.
    pub email: Option<String>,
    /// Optional profile image URL.
    pub image: Option<String>,
    /// Whether the provider confirms that the email address is verified.
    pub email_verified: bool,
}

// ----

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// OAuth state saved between authorization and callback requests.
pub struct OAuthTransaction {
    pub provider_id: String,
    pub code_verifier: String,
    pub callback_url: Option<String>,
}
