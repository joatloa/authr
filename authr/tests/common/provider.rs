use reqwest::Url;

use authr::core::{
    error::AuthrError,
    oauth::{
        OAuthProvider,
        types::{AuthorizationParams, ProviderUser, TokenExchangeParams, TokenResponse},
    },
};

pub struct MockOAuthProvider {
    pub fail_token_exchange: bool,
    pub fail_user_info: bool,
    pub scopes: Vec<String>,
}

impl MockOAuthProvider {
    pub fn new() -> Self {
        Self {
            fail_token_exchange: false,
            fail_user_info: false,
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
        }
    }
    pub fn failing_token_exchange() -> Self {
        Self {
            fail_token_exchange: true,
            ..Self::new()
        }
    }
    pub fn failing_user_info() -> Self {
        Self {
            fail_user_info: true,
            ..Self::new()
        }
    }
}

#[async_trait::async_trait]
impl OAuthProvider for MockOAuthProvider {
    fn id(&self) -> &'static str {
        "mock"
    }

    fn name(&self) -> &'static str {
        "Mock Provider"
    }

    fn scopes(&self) -> &[String] {
        &self.scopes
    }

    async fn create_authorization_url(
        &self,
        params: AuthorizationParams,
    ) -> Result<Url, AuthrError> {
        let mut url =
            Url::parse("https://mock.example/authorize").map_err(|_| AuthrError::Internal)?;

        url.query_pairs_mut()
            .append_pair("client_id", "mock-client")
            .append_pair("redirect_uri", params.redirect_uri.as_str())
            .append_pair("response_type", "code")
            .append_pair("state", &params.state)
            .append_pair("scope", &params.scopes.join(" "))
            .append_pair("code_challenge", &params.code_challenge)
            .append_pair("code_challenge_method", "S256");

        Ok(url)
    }

    async fn validate_authorization_code(
        &self,
        _params: TokenExchangeParams,
    ) -> Result<TokenResponse, AuthrError> {
        if self.fail_token_exchange {
            return Err(AuthrError::OAuthTokenExchangeFailed);
        }

        Ok(TokenResponse {
            access_token: "mock-access-token".into(),
            refresh_token: Some("mock-refresh-token".into()),
            id_token: Some("mock-id-token".into()),
            expires_in: Some(3600),
            scopes: vec!["openid".into(), "email".into()],
            token_type: Some("Bearer".into()),
        })
    }

    async fn refresh_access_token(
        &self,
        _refresh_token: &str,
    ) -> Result<TokenResponse, AuthrError> {
        Ok(TokenResponse {
            access_token: "refreshed-access-token".into(),
            refresh_token: None,
            id_token: None,
            expires_in: Some(3600),
            scopes: vec![],
            token_type: Some("Bearer".into()),
        })
    }

    async fn get_user_info(&self, _tokens: &TokenResponse) -> Result<ProviderUser, AuthrError> {
        if self.fail_user_info {
            return Err(AuthrError::OAuthUserInfoFailed);
        }

        Ok(ProviderUser {
            id: "mock-user-123".into(),
            name: Some("Mock User".into()),
            email: Some("mock@example.com".into()),
            image: Some("https://mock.example/avatar.png".into()),
            email_verified: true,
        })
    }
}
