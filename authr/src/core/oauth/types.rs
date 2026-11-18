use reqwest::Url;
use thiserror::Error;

pub struct AuthorizationParams {
    pub state: String,
    pub code_challenge: String,
    pub redirect_uri: Url,
    pub scopes: Vec<String>,
}

pub struct TokenExchangeParams {
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: Url,
}

pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub expires_in: Option<u64>,
    pub scopes: Vec<String>,
    pub token_type: Option<String>,
}

pub struct ProviderUser {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub image: Option<String>,
    pub email_verified: bool,
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("Invalid authorization code")]
    InvalidAuthorizationCode,
    #[error("Token exchange failed")]
    TokenExchangeFailed,
    #[error("Failed to retrieve user information")]
    UserInfoFailed,
    #[error("Failed to refresh access token")]
    TokenRefreshFailed,
    #[error("Invalid ID token")]
    InvalidIdToken,
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
}
