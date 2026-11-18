use async_trait::async_trait;
use reqwest::Url;

use crate::core::oauth::{
    providers::GoogleProvider,
    types::{AuthorizationParams, ProviderError, ProviderUser, TokenExchangeParams, TokenResponse},
};

#[derive(Debug, Clone)]
pub enum Provider {
    Google(GoogleProvider),
}

#[async_trait]
pub trait OAuthProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn scopes(&self) -> &[String];
    fn authorization_url(&self, params: AuthorizationParams) -> Result<Url, ProviderError>;
    async fn exchange_code(
        &self,
        params: TokenExchangeParams,
    ) -> Result<TokenResponse, ProviderError>;
    async fn get_user_info(&self, tokens: &TokenResponse) -> Result<ProviderUser, ProviderError>;
    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse, ProviderError>;
}

// -----
macro_rules! delegate_provider {
    ($self:expr, $method:ident ( $($arg:expr),* )) => {
        match $self {
            Provider::Google(provider) => provider.$method($($arg),*),
        }
    };
}
#[async_trait]
impl OAuthProvider for Provider {
    fn id(&self) -> &'static str {
        delegate_provider!(self, id())
    }

    fn scopes(&self) -> &[String] {
        delegate_provider!(self, scopes())
    }

    fn authorization_url(&self, params: AuthorizationParams) -> Result<Url, ProviderError> {
        delegate_provider!(self, authorization_url(params))
    }

    async fn exchange_code(
        &self,
        params: TokenExchangeParams,
    ) -> Result<TokenResponse, ProviderError> {
        delegate_provider!(self, exchange_code(params)).await
    }

    async fn get_user_info(&self, tokens: &TokenResponse) -> Result<ProviderUser, ProviderError> {
        delegate_provider!(self, get_user_info(tokens)).await
    }

    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse, ProviderError> {
        delegate_provider!(self, refresh_token(refresh_token)).await
    }
}
