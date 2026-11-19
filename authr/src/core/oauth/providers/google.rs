use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use crate::core::{
    error::AuthrError,
    oauth::{
        OAuthProvider,
        types::{AuthorizationParams, ProviderUser, TokenExchangeParams, TokenResponse},
    },
};

const AUTHORIZATION_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USER_INFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";

#[derive(Debug, Clone)]
pub struct GoogleProvider {
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    http: Client,
}

impl GoogleProvider {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            http: Client::new(),
        }
    }
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    name: Option<String>,
    email: Option<String>,
    picture: Option<String>,
    email_verified: Option<bool>,
}

impl From<GoogleUserInfo> for ProviderUser {
    fn from(user: GoogleUserInfo) -> Self {
        Self {
            id: user.sub,
            name: user.name,
            email: user.email,
            image: user.picture,
            email_verified: user.email_verified.unwrap_or(false),
        }
    }
}

impl GoogleProvider {
    fn build_token_response(
        response: GoogleTokenResponse,
        fallback_refresh_token: Option<String>,
    ) -> TokenResponse {
        TokenResponse {
            access_token: response.access_token,
            refresh_token: response.refresh_token.or(fallback_refresh_token),
            id_token: response.id_token,
            expires_in: response.expires_in,
            scopes: response
                .scope
                .map(|scope| scope.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default(),
            token_type: response.token_type,
        }
    }
}

// -------------------- OAuthProvider Implementation --------------------

#[async_trait]
impl OAuthProvider for GoogleProvider {
    fn id(&self) -> &'static str {
        "google"
    }
    fn name(&self) -> &'static str {
        "Google"
    }
    fn scopes(&self) -> &[String] {
        &self.scopes
    }
    async fn create_authorization_url(
        &self,
        params: AuthorizationParams,
    ) -> Result<Url, AuthrError> {
        let mut url = Url::parse(AUTHORIZATION_URL).map_err(|_| AuthrError::Internal)?;

        {
            let mut query = url.query_pairs_mut();

            query.append_pair("client_id", &self.client_id);
            query.append_pair("redirect_uri", params.redirect_uri.as_str());
            query.append_pair("response_type", "code");
            query.append_pair("state", &params.state);
            query.append_pair("code_challenge", &params.code_challenge);
            query.append_pair("code_challenge_method", "S256");

            for scope in params.scopes {
                query.append_pair("scope", &scope);
            }
        }

        Ok(url)
    }
    async fn validate_authorization_code(
        &self,
        params: TokenExchangeParams,
    ) -> Result<TokenResponse, AuthrError> {
        let response = self
            .http
            .post(TOKEN_URL)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", params.code.as_str()),
                ("code_verifier", params.code_verifier.as_str()),
                ("redirect_uri", params.redirect_uri.as_str()),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|_| AuthrError::OAuthTokenExchangeFailed)?
            .error_for_status()
            .map_err(|_| AuthrError::OAuthTokenExchangeFailed)?
            .json::<GoogleTokenResponse>()
            .await
            .map_err(|_| AuthrError::OAuthTokenExchangeFailed)?;

        Ok(Self::build_token_response(response, None))
    }
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenResponse, AuthrError> {
        let response = self
            .http
            .post(TOKEN_URL)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await
            .map_err(|_| AuthrError::OAuthTokenExchangeFailed)?
            .error_for_status()
            .map_err(|_| AuthrError::OAuthTokenExchangeFailed)?
            .json::<GoogleTokenResponse>()
            .await
            .map_err(|_| AuthrError::OAuthTokenExchangeFailed)?;

        Ok(Self::build_token_response(
            response,
            Some(refresh_token.to_owned()),
        ))
    }
    async fn get_user_info(&self, tokens: &TokenResponse) -> Result<ProviderUser, AuthrError> {
        let user = self
            .http
            .get(USER_INFO_URL)
            .bearer_auth(&tokens.access_token)
            .send()
            .await
            .map_err(|_| AuthrError::OAuthUserInfoFailed)?
            .error_for_status()
            .map_err(|_| AuthrError::OAuthUserInfoFailed)?
            .json::<GoogleUserInfo>()
            .await
            .map_err(|_| AuthrError::OAuthUserInfoFailed)?;

        Ok(user.into())
    }
}
