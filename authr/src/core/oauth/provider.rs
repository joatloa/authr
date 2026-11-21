use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;
use reqwest::Url;

use crate::core::{
    error::AuthrError,
    oauth::{
        providers::GoogleProvider,
        types::{AuthorizationParams, ProviderUser, TokenExchangeParams, TokenResponse},
    },
};

#[derive(Clone)]
pub enum Provider {
    Google(GoogleProvider),
    Custom(Arc<dyn OAuthProvider>),
}

impl Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Google(_) => f.debug_tuple("Google").finish(),
            Self::Custom(provider) => f.debug_tuple("Custom").field(&provider.id()).finish(),
        }
    }
}

#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// Returns the provider's unique identifier.
    fn id(&self) -> &'static str;
    /// Returns the provider's display name.
    fn name(&self) -> &'static str;
    /// Returns the default scopes requested from the provider.
    fn scopes(&self) -> &[String];
    /// Creates the authorization URL used to redirect the user to the provider.
    async fn create_authorization_url(
        &self,
        params: AuthorizationParams,
    ) -> Result<Url, AuthrError>;
    /// Exchanges an authorization code for OAuth tokens.
    async fn validate_authorization_code(
        &self,
        params: TokenExchangeParams,
    ) -> Result<TokenResponse, AuthrError>;
    /// Refreshes an expired access token.
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenResponse, AuthrError>;
    /// Retrieves and validates the authenticated user's profile.
    async fn get_user_info(&self, tokens: &TokenResponse) -> Result<ProviderUser, AuthrError>;
    /// Indicates whether the provider supports OpenID Connect RP-Initiated Logout.
    fn supports_end_session(&self) -> bool {
        false
    }
    /// Builds the provider's logout URL using the available session and redirect parameters.
    ///
    /// Returns `None` when the provider does not support logout or cannot generate a URL.
    async fn create_end_session_url(
        &self,
        _id_token: Option<&str>,
        _post_logout_redirect_uri: Option<&Url>,
        _state: Option<&str>,
    ) -> Result<Option<Url>, AuthrError> {
        Ok(None)
    }
}

// ----- OAuthProvider implementation foor Provider
macro_rules! delegate_provider {
    ($self:expr, $method:ident ( $($arg:expr),* )) => {
        match $self {
            Provider::Google(provider) => provider.$method($($arg),*),
            Provider::Custom(provider) => provider.$method($($arg),*),
        }
    };
}

#[async_trait]
impl OAuthProvider for Provider {
    fn id(&self) -> &'static str {
        delegate_provider!(self, id())
    }
    fn name(&self) -> &'static str {
        delegate_provider!(self, name())
    }
    fn scopes(&self) -> &[String] {
        delegate_provider!(self, scopes())
    }
    async fn create_authorization_url(
        &self,
        params: AuthorizationParams,
    ) -> Result<Url, AuthrError> {
        delegate_provider!(self, create_authorization_url(params)).await
    }
    async fn validate_authorization_code(
        &self,
        params: TokenExchangeParams,
    ) -> Result<TokenResponse, AuthrError> {
        delegate_provider!(self, validate_authorization_code(params)).await
    }
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenResponse, AuthrError> {
        delegate_provider!(self, refresh_access_token(refresh_token)).await
    }
    async fn get_user_info(&self, tokens: &TokenResponse) -> Result<ProviderUser, AuthrError> {
        delegate_provider!(self, get_user_info(tokens)).await
    }
    fn supports_end_session(&self) -> bool {
        delegate_provider!(self, supports_end_session())
    }
    async fn create_end_session_url(
        &self,
        id_token: Option<&str>,
        post_logout_redirect_uri: Option<&Url>,
        state: Option<&str>,
    ) -> Result<Option<Url>, AuthrError> {
        delegate_provider!(
            self,
            create_end_session_url(id_token, post_logout_redirect_uri, state)
        )
        .await
    }
}
