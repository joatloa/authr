use actix_web::{HttpRequest, HttpResponse, Responder, http::header, web};
use serde::Deserialize;
use serde_json::json;

use crate::{
    core::{auth::AuthrContext, oauth::OAuthProvider},
    database::store::AuthDatabase,
    http::utils::{SESSION_COOKIE_NAME, get_removal_session_cookie},
};

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
) -> impl Responder {
    let SignOutRequest {
        callback_url,
        disable_redirect,
        state,
    } = body.into_inner();

    // ----- Extract session token
    let session_token = req
        .cookie(SESSION_COOKIE_NAME)
        .map(|cookie| cookie.value().to_string());

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

    // ----- Clear session cookie
    let cookie = get_removal_session_cookie();

    tracing::debug!("Session cookie scheduled for removal");

    // ----- Provider logout
    let provider_logout_url = if let Some(session) = current_session {
        tracing::debug!(
            user_id = %session.user_id,
            "Attempting provider logout"
        );

        create_provider_logout_url(
            &req,
            &ctx,
            session.user_id,
            callback_url.as_deref(),
            state.as_deref(),
        )
        .await
    } else {
        tracing::debug!("Skipping provider logout: no active session");
        None
    };

    // ----- Response
    let mut response = HttpResponse::Ok();

    if let Some(url) = provider_logout_url {
        let should_redirect = !disable_redirect;

        if should_redirect {
            tracing::info!("Redirecting to provider logout");
            response.insert_header((header::LOCATION, url.as_str()));
        } else {
            tracing::debug!("Returning provider logout URL without redirect");
        }

        return response.cookie(cookie).json(json!({
            "success": true,
            "url": url,
            "redirect": should_redirect
        }));
    }

    tracing::info!("Local sign-out completed");

    response.cookie(cookie).json(json!({
        "success": true
    }))
}

// ----- Provider logout

#[tracing::instrument(
    name = "auth.provider_logout",
    skip_all,
    fields(user_id = %user_id),
)]
async fn create_provider_logout_url<D: AuthDatabase + 'static>(
    req: &HttpRequest,
    ctx: &web::Data<AuthrContext<D>>,
    user_id: uuid::Uuid,
    callback_url: Option<&str>,
    state: Option<&str>,
) -> Option<String> {
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
            return None;
        }
    };

    // ----- Filter supported providers
    let mut accounts: Vec<_> = accounts
        .into_iter()
        .filter(|account| {
            ctx.config()
                .social_providers
                .get(&account.provider_id)
                .is_some_and(|provider| provider.supports_end_session())
        })
        .collect();

    tracing::debug!(
        supported_account_count = accounts.len(),
        "Filtered accounts supporting provider logout"
    );

    // ----- Sort by most recently updated
    accounts.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

    // ----- Resolve post-logout redirect URI
    let post_logout_redirect_uri = match callback_url {
        Some(callback_url) => {
            let base_url = match ctx.config().base_url.resolve(req) {
                Ok(url) => {
                    tracing::debug!(%url, "Resolved base URL for provider logout");
                    url
                }
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        "Failed to resolve base URL"
                    );
                    return None;
                }
            };

            match base_url.join(callback_url) {
                Ok(url) => {
                    tracing::debug!(
                        %url,
                        "Resolved post-logout redirect URI"
                    );
                    Some(url)
                }
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        "Invalid logout callback URL"
                    );
                    return None;
                }
            }
        }
        None => {
            tracing::debug!("No post-logout callback URL provided");
            None
        }
    };

    // ----- Generate provider logout URL
    let mut seen_provider_ids = std::collections::HashSet::new();

    for account in accounts {
        if !seen_provider_ids.insert(account.provider_id.clone()) {
            continue;
        }

        let Some(provider) = ctx.config().social_providers.get(&account.provider_id) else {
            tracing::debug!(
                provider = %account.provider_id,
                "Provider configuration not found"
            );
            continue;
        };

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
                return Some(url.to_string());
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

    None
}
