use actix_web::{HttpRequest, HttpResponse, web};
use chrono::Utc;
use serde::Deserialize;

use crate::{
    core::{
        auth::AuthrContext,
        error::AuthrError,
        oauth::{
            OAuthProvider,
            types::{OAuthTransaction, ProviderUser, TokenExchangeParams, TokenResponse},
            utils::get_provider_callback_url,
        },
        types::{Account, Session, User},
        utils::get_base_url,
    },
    database::store::AuthDatabase,
    http::utils::get_session_cookie,
};

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub state: Option<String>,
}

#[tracing::instrument(
    name = "auth.oauth_callback",
    skip_all,
    fields(
        provider = %path.as_str(),
        has_code = query.code.is_some(),
        has_state = query.state.is_some()
    ),
    err
)]
pub async fn callback<D: AuthDatabase + 'static>(
    req: HttpRequest,
    query: web::Query<OAuthCallbackQuery>,
    ctx: web::Data<AuthrContext<D>>,
    path: web::Path<String>,
) -> Result<HttpResponse, AuthrError> {
    let provider_id = path.into_inner();

    let OAuthCallbackQuery {
        code,
        error,
        error_description,
        state,
    } = query.into_inner();

    // ----- Create closure to redirect when an error happens
    let mut error_url = get_base_url(&ctx.config().base_url, &req)?;
    error_url.set_path(&format!(
        "{}/error",
        ctx.config().base_path.trim_end_matches('/')
    ));

    let redirect_error = |error: &str, error_description: Option<String>| -> HttpResponse {
        let mut url = error_url.clone();
        url.query_pairs_mut().append_pair("error", error);

        if let Some(err_desc) = error_description {
            url.query_pairs_mut()
                .append_pair("error_description", &err_desc);
        }

        HttpResponse::Found()
            .append_header(("Location", url.to_string()))
            .finish()
    };

    // ----- Authorization Error
    if let Some(error) = error {
        tracing::warn!(
            provider = %provider_id,
            "OAuth authorization failed"
        );

        tracing::debug!(
            has_error_description = error_description.is_some(),
            "Received OAuth authorization error response"
        );

        return Ok(redirect_error(&error, error_description));
    }

    // ----- State Validation
    let Some(state) = state else {
        tracing::warn!(
            provider = %provider_id,
            "OAuth callback received without state"
        );

        return Ok(redirect_error("state_not_found", None));
    };

    // Retrieve and consume the OAuth transaction.
    let identifier = format!("oauth:{state}");

    let verification = match ctx.store().consume_verification(&identifier).await {
        Ok(Some(verification)) => verification,
        Ok(None) => {
            tracing::warn!(
                provider = %provider_id,
                "OAuth state not found or already consumed"
            );

            return Ok(redirect_error("invalid_state", None));
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "Failed to consume OAuth state"
            );

            return Ok(redirect_error("invalid_state", None));
        }
    };

    tracing::debug!("OAuth state consumed successfully");

    // ----- Deserialize OAuth Transaction
    let transaction: OAuthTransaction = match serde_json::from_str(&verification.value) {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::error!(
                error = %error,
                "Failed to deserialize OAuth transaction"
            );

            return Ok(redirect_error("invalid_state", None));
        }
    };

    // ----- Validate OAuth Transaction
    if transaction.provider_id != provider_id {
        tracing::warn!(
            provider = %provider_id,
            transaction_provider = %transaction.provider_id,
            "OAuth provider mismatch"
        );

        return Ok(redirect_error("provider_mismatch", None));
    }

    if verification.expires_at <= Utc::now() {
        tracing::warn!(
            provider = %provider_id,
            "OAuth state has expired"
        );

        return Ok(redirect_error("state_expired", None));
    }

    // ----- Provider Resolution
    let Some(provider) = ctx.config().social_providers.get(&provider_id) else {
        tracing::warn!(
            provider = %provider_id,
            "OAuth provider is not configured"
        );

        return Ok(redirect_error("provider_not_found", None));
    };

    let Some(code) = code else {
        tracing::warn!(
            provider = %provider_id,
            "OAuth callback received without authorization code"
        );

        return Ok(redirect_error("code_not_found", None));
    };

    // ----- Build Callback URL
    let redirect_uri = match get_provider_callback_url(
        &ctx.config().base_url,
        &ctx.config().base_path,
        &req,
        provider.id(),
    ) {
        Ok(url) => url,
        Err(error) => {
            tracing::error!(
                error = %error,
                "Failed to create provider callback URL"
            );

            return Ok(redirect_error("invalid_callback_url", None));
        }
    };

    // ----- Token Exchange
    let tokens = match provider
        .validate_authorization_code(TokenExchangeParams {
            code,
            code_verifier: transaction.code_verifier,
            redirect_uri,
        })
        .await
    {
        Ok(tokens) => tokens,
        Err(error) => {
            tracing::error!(
                provider = %provider_id,
                error = %error,
                "OAuth token exchange failed"
            );

            return Ok(redirect_error("token_exchange_failed", None));
        }
    };

    tracing::debug!(
        provider = %provider_id,
        "OAuth token exchange completed successfully"
    );

    // ----- User Resolution
    let provider_user = match provider.get_user_info(&tokens).await {
        Ok(user) => user,
        Err(error) => {
            tracing::error!(
                provider = %provider_id,
                error = %error,
                "Failed to retrieve provider user"
            );

            return Ok(redirect_error("user_info_failed", None));
        }
    };

    if provider_user.email.is_none() {
        tracing::warn!(
            provider = %provider_id,
            "OAuth provider did not return an email address"
        );

        return Ok(redirect_error("email_not_found", None));
    }

    let user = match resolve_oauth_user(&ctx, &provider_id, &provider_user, &tokens).await {
        Ok(user) => user,
        Err(error) => {
            tracing::error!(
                provider = %provider_id,
                error = %error,
                "Failed to resolve OAuth user"
            );

            return Ok(redirect_error("account_linking_failed", None));
        }
    };

    // ----- Session Creation
    let ip_address = req.peer_addr().map(|address| address.ip().to_string());
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let session = match ctx
        .store()
        .create_session(Session::new(user.id, ip_address, user_agent), true)
        .await
    {
        Ok(session) => session,
        Err(error) => {
            tracing::error!(
                error = %error,
                "Failed to create session"
            );

            return Ok(redirect_error("session_creation_failed", None));
        }
    };

    tracing::info!(
        provider = %provider_id,
        "User signed in successfully through OAuth"
    );

    // ----- Application Redirect
    let Some(callback_url) = transaction.callback_url else {
        tracing::warn!(
            provider = %provider_id,
            "OAuth transaction does not contain an application callback URL"
        );

        return Ok(redirect_error("callback_url_not_found", None));
    };

    let cookie = get_session_cookie(&session);

    tracing::debug!(
        provider = %provider_id,
        "Redirecting user to application callback URL"
    );

    Ok(HttpResponse::Found()
        .append_header(("Location", callback_url))
        .cookie(cookie)
        .finish())
}

#[tracing::instrument(
    name = "auth.resolve_oauth_user",
    skip_all,
    fields(provider = %provider_id),
    err
)]
async fn resolve_oauth_user<D: AuthDatabase + 'static>(
    ctx: &AuthrContext<D>,
    provider_id: &str,
    provider_user: &ProviderUser,
    tokens: &TokenResponse,
) -> Result<User, AuthrError> {
    // ----- Existing Account
    if let Some(account) = ctx
        .store()
        .find_account_by_provider(provider_id, &provider_user.id)
        .await?
    {
        tracing::debug!(
            provider = %provider_id,
            "Existing OAuth account found"
        );

        return ctx
            .store()
            .find_user_by_id(&account.user_id.to_string())
            .await?
            .ok_or(AuthrError::UserNotFound);
    }

    // ----- User Resolution
    let email = provider_user
        .email
        .as_deref()
        .ok_or(AuthrError::InvalidEmail)?;

    let user = match ctx.store().find_user_by_email(email).await? {
        Some(user) => {
            tracing::debug!(
                provider = %provider_id,
                "Existing user found for OAuth email"
            );

            user
        }

        // If user doesn't exist, create one.
        None => {
            let user = ctx
                .store()
                .create_user(User::new(
                    provider_user.name.clone().unwrap_or_default(),
                    email.to_string(),
                    provider_user.email_verified,
                    provider_user.image.clone(),
                ))
                .await?;

            tracing::info!(
                provider = %provider_id,
                "Created user through OAuth sign-in"
            );

            user
        }
    };

    // ----- Account Linking
    ctx.store()
        .create_account(Account::new_social(
            user.id,
            provider_id.to_string(),
            provider_user.id.clone(),
            Some(tokens.access_token.clone()),
            tokens.refresh_token.clone(),
            tokens
                .expires_in
                .map(|seconds| Utc::now() + chrono::Duration::seconds(seconds as i64)),
            None,
            Some(tokens.scopes.join(",")),
            tokens.id_token.clone(),
        ))
        .await?;

    tracing::info!(
        provider = %provider_id,
        "OAuth account linked successfully"
    );

    Ok(user)
}
