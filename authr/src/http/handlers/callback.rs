use actix_web::{HttpRequest, HttpResponse, web};
use chrono::Utc;
use serde::Deserialize;

use crate::{
    core::{
        auth::AuthrData,
        error::AuthrError,
        oauth::{
            OAuthProvider,
            types::{OAuthTransaction, ProviderUser, TokenExchangeParams, TokenResponse},
            utils::get_provider_callback_url,
        },
        types::{Account, Session, User},
        utils::get_base_url,
    },
    database::store::{AuthDatabase, UserQuery},
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
    fields(provider = %path.as_str())
)]
pub async fn callback<D: AuthDatabase + 'static>(
    req: HttpRequest,
    query: web::Query<OAuthCallbackQuery>,
    data: web::Data<AuthrData<D>>,
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
    let mut error_url = get_base_url(&data.config.base_url, &req)?;
    error_url.set_path(&format!(
        "{}/error",
        data.config.base_path.trim_end_matches('/')
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
            error = %error,
            description = ?error_description,
            "OAuth authorization failed"
        );

        return Ok(redirect_error(&error, error_description));
    }

    // ----- State Validation
    let Some(state) = state else {
        return Ok(redirect_error("state_not_found", None));
    };

    // Retrieve and consume the OAuth transaction.
    let identifier = format!("oauth:{state}");
    let verification = match data.database.consume_verification(&identifier).await {
        Ok(Some(verification)) => verification,
        Ok(None) => return Ok(redirect_error("invalid_state", None)),
        Err(error) => {
            tracing::error!(error = %error, "Failed to consume OAuth state");
            return Ok(redirect_error("invalid_state", None));
        }
    };

    // Deserialize the OAuth transaction.
    let transaction: OAuthTransaction = match serde_json::from_str(&verification.value) {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::error!(error = %error, "Invalid OAuth transaction");
            return Ok(redirect_error("invalid_state", None));
        }
    };

    // Make sure the transaction belongs to this provider and hasn't expired.
    if transaction.provider_id != provider_id {
        return Ok(redirect_error("provider_mismatch", None));
    }

    if verification.expires_at <= Utc::now() {
        return Ok(redirect_error("state_expired", None));
    }

    // ----- Provider Resolution
    let Some(provider) = data.config.social_providers.get(&provider_id) else {
        return Ok(redirect_error("provider_not_found", None));
    };

    let Some(code) = code else {
        return Ok(redirect_error("code_not_found", None));
    };

    // Generate the same redirect URI used during authorization.
    let redirect_uri = match get_provider_callback_url(
        &data.config.base_url,
        &data.config.base_path,
        &req,
        provider.id(),
    ) {
        Ok(url) => url,
        Err(error) => {
            tracing::error!(error = %error, "Failed to create provider callback URL");
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
            tracing::error!(error = %error, "OAuth token exchange failed");
            return Ok(redirect_error("token_exchange_failed", None));
        }
    };

    // ----- User Resolution
    let provider_user = match provider.get_user_info(&tokens).await {
        Ok(user) => user,
        Err(error) => {
            tracing::error!(error = %error, "Failed to retrieve provider user");
            return Ok(redirect_error("user_info_failed", None));
        }
    };

    if provider_user.email.is_none() {
        return Ok(redirect_error("email_not_found", None));
    }

    let user = match resolve_oauth_user(&data, &provider_id, &provider_user, &tokens).await {
        Ok(user) => user,
        Err(error) => {
            tracing::error!(error = %error, "Failed to resolve OAuth user");
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

    let session = match data
        .database
        .create_session(Session::new(user.id, ip_address, user_agent), true)
        .await
    {
        Ok(session) => session,
        Err(error) => {
            tracing::error!(error = %error, "Failed to create session");
            return Ok(redirect_error("session_creation_failed", None));
        }
    };

    // ----- Application Redirect
    let Some(callback_url) = transaction.callback_url else {
        return Ok(redirect_error("callback_url_not_found", None));
    };

    let cookie = get_session_cookie(&session);

    Ok(HttpResponse::Found()
        .append_header(("Location", callback_url))
        .cookie(cookie)
        .finish())
}

async fn resolve_oauth_user<D: AuthDatabase + 'static>(
    data: &AuthrData<D>,
    provider_id: &str,
    provider_user: &ProviderUser,
    tokens: &TokenResponse,
) -> Result<User, AuthrError> {
    // ----- Existing Account
    if let Some(account) = data
        .database
        .find_account(crate::database::store::AccountQuery::Provider {
            provider_id,
            account_id: &provider_user.id,
        })
        .await?
    {
        return data
            .database
            .find_user(UserQuery::Id(&account.user_id.to_string()))
            .await?
            .ok_or(AuthrError::UserNotFound);
    }

    // ----- User Resolution
    let email = provider_user
        .email
        .as_deref()
        .ok_or(AuthrError::InvalidEmail)?;
    let user = match data.database.find_user(UserQuery::Email(email)).await? {
        Some(user) => user,
        // If user doesn't exist create one
        None => {
            data.database
                .create_user(User::new(
                    provider_user.name.clone().unwrap_or_default(),
                    email.to_string(),
                    provider_user.email_verified,
                    provider_user.image.clone(),
                ))
                .await?
        }
    };

    // ----- Account Linking
    data.database
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

    Ok(user)
}
