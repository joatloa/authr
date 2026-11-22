use actix_web::{HttpRequest, HttpResponse, http::header, web};
use serde::Deserialize;
use serde_json::json;

use crate::{
    core::{auth::AuthrContext, error::AuthrError, oauth::OAuthProvider},
    database::store::AuthDatabase,
    http::cookie::{build_removal_session_cookie, extract_session_token},
};

// -------------------- Sign Out - POST "/sign-up" --------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignOutRequest {
    /// The URL to redirect to after provider logout
    callback_url: Option<String>,
    /// Return the provider logout URL without redirecting
    #[serde(default)]
    disable_redirect: bool,
    /// State to pass to the provider logout endpoint
    state: Option<String>,
}

#[tracing::instrument(
    name = "auth.sign_out",
    skip_all,
    fields(
        disable_redirect = body.disable_redirect,
        has_callback_url = body.callback_url.is_some(),
        has_state = body.state.is_some()
    )
)]
pub async fn sign_out<D: AuthDatabase + 'static>(
    req: HttpRequest,
    ctx: web::Data<AuthrContext<D>>,
    body: web::Json<SignOutRequest>,
) -> Result<HttpResponse, AuthrError> {
    let body = body.into_inner();

    // ----- Extract session token
    let session_token = extract_session_token(&req);

    if session_token.is_some() {
        tracing::debug!("Session cookie found in sign-out request");
    } else {
        tracing::debug!("Sign-out requested without a session cookie");
    }

    // ----- Read current session
    let current_session = if let Some(token) = &session_token {
        match ctx.store().find_session_by_token(token).await {
            Ok(Some(session)) => {
                tracing::debug!(
                    session_id = %session.id,
                    user_id = %session.user_id,
                    "Current session found"
                );
                Some(session)
            }
            Ok(None) => {
                tracing::debug!("No matching session found");
                None
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "Failed to read session from database"
                );
                None
            }
        }
    } else {
        None
    };

    // ----- Revoke session
    if let Some(token) = &session_token {
        match ctx.store().delete_session_by_token(token).await {
            Ok(true) => {
                tracing::info!("Session revoked successfully");
            }
            Ok(false) => {
                tracing::debug!("No matching session found to revoke");
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "Failed to revoke session"
                );
            }
        }
    }

    // ----- Provider logout
    let provider_logout_url = if let Some(session) = current_session {
        tracing::debug!(
            user_id = %session.user_id,
            "Attempting provider logout"
        );

        match create_provider_logout_url(
            &ctx,
            &req,
            session.user_id,
            body.callback_url.as_deref(),
            body.state.as_deref(),
        )
        .await
        {
            Ok(url) => url,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "Failed to generate provider logout URL"
                );
                None
            }
        }
    } else {
        tracing::debug!("Skipping provider logout: no active session");
        None
    };

    // ----- Response
    let cookie = build_removal_session_cookie();

    let mut response = HttpResponse::Ok();

    if let Some(url) = provider_logout_url {
        let should_redirect = !body.disable_redirect;

        if should_redirect {
            tracing::info!("Redirecting to provider logout");
            response.insert_header((header::LOCATION, url.as_str()));
        } else {
            tracing::debug!("Returning provider logout URL without redirect");
        }

        return Ok(response.cookie(cookie).json(json!({
            "success": true,
            "url": url,
            "redirect": should_redirect
        })));
    }

    tracing::info!("Local sign-out completed");

    Ok(response.cookie(cookie).json(json!({
        "success": true
    })))
}

// -------------------- Helpers --------------------

async fn create_provider_logout_url<D: AuthDatabase + 'static>(
    ctx: &web::Data<AuthrContext<D>>,
    req: &HttpRequest,
    user_id: uuid::Uuid,
    callback_url: Option<&str>,
    state: Option<&str>,
) -> Result<Option<String>, AuthrError> {
    let config = ctx.config();

    // ----- Resolve post-logout redirect URI
    let post_logout_redirect_uri = match callback_url {
        Some(callback_url) => {
            let connection = req.connection_info();

            let base_url = config
                .base_url
                .resolve(Some(connection.host()), Some(connection.scheme()))?;

            tracing::debug!(%base_url, "Resolved base URL for provider logout");

            let url = base_url
                .join(callback_url)
                .map_err(|_| AuthrError::Internal)?;

            if !config.base_url.is_allowed(url.as_str()) {
                return Err(AuthrError::InvalidCallbackUrl);
            }

            tracing::debug!(
                %url,
                "Resolved post-logout redirect URI"
            );

            Some(url)
        }
        None => {
            tracing::debug!("No post-logout callback URL provided");
            None
        }
    };

    // ----- Find linked accounts
    let accounts = match ctx
        .store()
        .find_accounts_by_user_id(&user_id.to_string())
        .await
    {
        Ok(accounts) => {
            tracing::debug!(account_count = accounts.len(), "Retrieved linked accounts");
            accounts
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "Failed to find user accounts"
            );
            return Err(error);
        }
    };

    // ----- Filter supported providers
    let mut accounts: Vec<_> = accounts
        .into_iter()
        .filter_map(|account| {
            let provider = config.social_providers.get(&account.provider_id)?;

            provider
                .supports_end_session()
                .then_some((account, provider))
        })
        .collect();

    // ----- Sort by most recently updated
    accounts.sort_by(|a, b| b.0.updated_at.cmp(&a.0.updated_at));

    // ----- Generate provider logout URL
    let mut seen_provider_ids = std::collections::HashSet::new();

    for (account, provider) in accounts {
        if !seen_provider_ids.insert(account.provider_id.clone()) {
            continue;
        }

        tracing::debug!(
            provider = %account.provider_id,
            "Attempting provider logout URL generation"
        );

        match provider
            .create_end_session_url(
                account.id_token.as_deref(),
                post_logout_redirect_uri.as_ref(),
                state,
            )
            .await
        {
            Ok(Some(url)) => {
                tracing::info!(
                    provider = %account.provider_id,
                    "Provider logout URL generated successfully"
                );
                return Ok(Some(url.to_string()));
            }
            Ok(None) => {
                tracing::debug!(
                    provider = %account.provider_id,
                    "Provider does not provide a logout URL"
                );
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    provider = %account.provider_id,
                    "Failed to create provider logout URL"
                );
            }
        }
    }

    tracing::debug!("No provider logout URL could be generated");

    Ok(None)
}
