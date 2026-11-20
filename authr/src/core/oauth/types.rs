use reqwest::Url;
use serde::{Deserialize, Serialize};

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

// ----

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthTransaction {
    pub provider_id: String,
    pub code_verifier: String,
    pub callback_url: Option<String>,
}
