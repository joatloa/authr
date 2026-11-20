use actix_web::{
    HttpRequest, HttpResponse, Responder,
    cookie::{Cookie, SameSite},
    http::header,
    web,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    core::{auth::AuthrData, oauth::OAuthProvider, utils::get_base_url},
    database::store::{AccountQuery, AuthDatabase, SessionQuery},
    http::utils::SESSION_COOKIE_NAME,
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

#[tracing::instrument(name = "auth.sign_out", skip_all)]
pub async fn sign_out<D: AuthDatabase + 'static>(
    req: HttpRequest,
    data: web::Data<AuthrData<D>>,
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

    // ----- Read current session
    let current_session = if let Some(token) = &session_token {
        match data.database.find_session(SessionQuery::Token(token)).await {
            Ok(session) => session,
            Err(error) => {
                tracing::error!(error = %error, "Failed to read session from database");
                None
            }
        }
    } else {
        None
    };

    // ----- Revoke session
    if let Some(token) = &session_token {
        match data
            .database
            .delete_session(SessionQuery::Token(token))
            .await
        {
            Ok(true) => tracing::info!("Session revoked successfully"),
            Ok(false) => tracing::debug!("No matching session found"),
            Err(error) => {
                tracing::error!(error = %error, "Failed to revoke session");
            }
        }
    }

    // ----- Clear session cookie
    let mut cookie = Cookie::build(SESSION_COOKIE_NAME, "")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .finish();

    cookie.make_removal();

    // ----- Provider logout
    let provider_logout_url = if let Some(session) = current_session {
        create_provider_logout_url(
            &req,
            &data,
            session.user_id,
            callback_url.as_deref(),
            state.as_deref(),
        )
        .await
    } else {
        None
    };

    // ----- Response
    let mut response = HttpResponse::Ok();

    if let Some(url) = provider_logout_url {
        let should_redirect = !disable_redirect;

        if should_redirect {
            response.insert_header((header::LOCATION, url.as_str()));
        }

        return response.cookie(cookie).json(json!({
            "success": true,
            "url": url,
            "redirect": should_redirect
        }));
    }

    response.cookie(cookie).json(json!({
        "success": true
    }))
}

// ----- Provider logout
async fn create_provider_logout_url<D: AuthDatabase + 'static>(
    req: &HttpRequest,
    data: &web::Data<AuthrData<D>>,
    user_id: uuid::Uuid,
    callback_url: Option<&str>,
    state: Option<&str>,
) -> Option<String> {
    // ----- Find linked accounts
    let accounts = match data
        .database
        .find_accounts(AccountQuery::UserId(&user_id.to_string()))
        .await
    {
        Ok(accounts) => accounts,
        Err(error) => {
            tracing::error!(error = %error, "Failed to find user accounts");
            return None;
        }
    };

    // ----- Filter supported providers
    let mut accounts: Vec<_> = accounts
        .into_iter()
        .filter(|account| {
            data.config
                .social_providers
                .get(&account.provider_id)
                .is_some_and(|provider| provider.supports_end_session())
        })
        .collect();

    // ----- Sort by most recently updated
    accounts.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

    // ----- Resolve post-logout redirect URI
    let post_logout_redirect_uri = match callback_url.as_deref() {
        Some(callback_url) => {
            let base_url = match get_base_url(&data.config.base_url, req) {
                Ok(url) => url,
                Err(error) => {
                    tracing::error!(error = %error, "Failed to resolve base URL");
                    return None;
                }
            };

            match base_url.join(callback_url) {
                Ok(url) => Some(url),
                Err(error) => {
                    tracing::error!(error = %error, "Invalid logout callback URL");
                    return None;
                }
            }
        }
        None => None,
    };

    // ----- Generate provider logout URL
    let mut seen_provider_ids = std::collections::HashSet::new();

    for account in accounts {
        if !seen_provider_ids.insert(account.provider_id.clone()) {
            continue;
        }

        let Some(provider) = data.config.social_providers.get(&account.provider_id) else {
            continue;
        };

        match provider
            .create_end_session_url(
                account.id_token.as_deref(),
                post_logout_redirect_uri.as_ref(),
                state,
            )
            .await
        {
            Ok(Some(url)) => return Some(url.to_string()),
            Ok(None) => {}
            Err(error) => {
                tracing::error!(
                    error = %error,
                    provider = %account.provider_id,
                    "Failed to create provider logout URL"
                );
            }
        }
    }

    None
}
