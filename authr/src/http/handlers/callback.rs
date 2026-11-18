use actix_web::{HttpResponse, Responder, get, web};
use chrono::Utc;
use serde::Deserialize;
use url::Url;
use uuid::Uuid;

use crate::{
    core::{
        auth::AuthrData,
        error::AuthrError,
        oauth::{
            OAuthProvider,
            types::{ProviderUser, TokenExchangeParams, TokenResponse},
            utils::get_provider_callback_url,
        },
        types::{Account, User},
    },
    database::store::{AccountsStore, SessionsStore, UsersStore, VerificationStore},
    http::utils::get_session_cookie,
};

#[derive(Debug, Deserialize)]
struct OAuthCallbackQuery {
    code: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OAuthTransaction {
    provider_id: String,
    code_verifier: String,
    callback_url: Option<String>,
}

#[get("/callback/{provider}")]
pub async fn callback(
    data: web::Data<AuthrData>,
    path: web::Path<String>,
    query: web::Query<OAuthCallbackQuery>,
) -> impl Responder {
    let provider_id = path.into_inner();
    let OAuthCallbackQuery {
        code,
        error,
        error_description,
        state,
    } = query.into_inner();

    // Where the user is redirected when the OAuth flow fails.
    let error_url = format!("{}/error", data.base_url);
    let redirect_error = |error: &str| -> HttpResponse {
        let mut url = match Url::parse(&error_url) {
            Ok(url) => url,
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };

        url.query_pairs_mut().append_pair("error", error);

        HttpResponse::Found()
            .append_header(("Location", url.to_string()))
            .finish()
    };

    // 1. Check whether the provider returned an OAuth error.
    if let Some(error) = error {
        eprintln!(
            "OAuth authorization failed: {}",
            error_description.as_deref().unwrap_or(&error)
        );

        return redirect_error(&error);
    }

    // 2. Validate the state.
    let Some(state) = state else {
        return redirect_error("state_not_found");
    };

    // 3. Retrieve and consume the OAuth transaction.
    //
    // This operation should be atomic: retrieve the verification
    // and delete it in one database transaction.
    let identifier = format!("oauth:{state}");

    let verification = match data.database.consume_verification(&identifier).await {
        Ok(Some(verification)) => verification,
        Ok(None) => return redirect_error("invalid_state"),
        Err(error) => {
            eprintln!("Failed to consume OAuth state: {error}");
            return redirect_error("invalid_state");
        }
    };

    let transaction: OAuthTransaction = match serde_json::from_str(&verification.value) {
        Ok(transaction) => transaction,
        Err(error) => {
            eprintln!("Invalid OAuth transaction: {error}");
            return redirect_error("invalid_state");
        }
    };

    // 4. Make sure the transaction belongs to this provider.
    if transaction.provider_id != provider_id {
        return redirect_error("provider_mismatch");
    }

    // 5. Check the transaction expiration.
    if verification.expires_at <= Utc::now() {
        return redirect_error("state_expired");
    }

    // 6. Retrieve the provider.
    let Some(provider) = data.providers.get(&provider_id) else {
        return redirect_error("provider_not_found");
    };

    // 7. Make sure we received an authorization code.
    let Some(code) = code else {
        return redirect_error("code_not_found");
    };

    // 8. Generate the same redirect URI used during authorization.
    let redirect_uri = match get_provider_callback_url(&data.base_url, provider.id()) {
        Ok(url) => url,
        Err(error) => {
            eprintln!("Failed to create provider callback URL: {error}");
            return redirect_error("invalid_callback_url");
        }
    };

    // 9. Exchange the authorization code for tokens.
    let tokens = match provider
        .exchange_code(TokenExchangeParams {
            code,
            code_verifier: transaction.code_verifier,
            redirect_uri,
        })
        .await
    {
        Ok(tokens) => tokens,
        Err(error) => {
            eprintln!("OAuth token exchange failed: {error}");
            return redirect_error("token_exchange_failed");
        }
    };

    // 10. Retrieve the provider user's information.
    let provider_user = match provider.get_user_info(&tokens).await {
        Ok(user) => user,
        Err(error) => {
            eprintln!("Failed to retrieve provider user: {error}");
            return redirect_error("user_info_failed");
        }
    };

    // 11. An email is required for the initial implementation.
    let Some(_email) = provider_user.email.clone() else {
        return redirect_error("email_not_found");
    };

    // 12. Resolve the local user and linked account.
    let user = match resolve_oauth_user(&data, &provider_id, &provider_user, &tokens).await {
        Ok(user) => user,
        Err(error) => {
            eprintln!("Failed to resolve OAuth user: {error}");
            return redirect_error("account_linking_failed");
        }
    };

    // 13. Create a local session.
    let session = match data
        .database
        .create_session(&user.id.to_string(), true)
        .await
    {
        Ok(session) => session,
        Err(error) => {
            eprintln!("Failed to create session: {error}");
            return redirect_error("session_creation_failed");
        }
    };

    // 14. Set the local session cookie.
    let cookie = get_session_cookie(&session);

    // 15. Redirect the user back to the application.
    let Some(callback_url) = transaction.callback_url else {
        return redirect_error("callback_url_not_found");
    };

    HttpResponse::Found()
        .append_header(("Location", callback_url))
        .cookie(cookie)
        .finish()
}

async fn resolve_oauth_user(
    data: &AuthrData,
    provider_id: &str,
    provider_user: &ProviderUser,
    tokens: &TokenResponse,
) -> Result<User, AuthrError> {
    // 1. Look for an existing provider account.
    if let Some(account) = data
        .database
        .find_account(provider_id, &provider_user.id)
        .await?
    {
        return data
            .database
            .find_user_by_id(&account.user_id.to_string())
            .await?
            .ok_or(AuthrError::UserNotFound);
    }

    let email = provider_user
        .email
        .as_deref()
        .ok_or(AuthrError::InvalidEmail)?;

    // 2. Look for an existing local user with this email.
    let user = match data.database.find_user_by_email(email).await? {
        Some(user) => user,

        // 3. Otherwise, create a new local user.
        None => {
            let now = Utc::now();

            let user = User {
                id: Uuid::new_v4(),
                name: provider_user.name.clone().unwrap_or_default(),
                email: email.to_string(),
                email_verified: provider_user.email_verified,
                image: provider_user.image.clone(),
                created_at: now,
                updated_at: now,
            };

            data.database.create_user(user).await?
        }
    };

    // 4. Link the provider account to the local user.
    let now = Utc::now();

    let account = Account {
        id: Uuid::new_v4(),
        user_id: user.id,
        account_id: provider_user.id.clone(),
        provider_id: provider_id.to_string(),
        access_token: Some(tokens.access_token.clone()),
        refresh_token: tokens.refresh_token.clone(),
        access_token_expires_at: tokens
            .expires_in
            .map(|seconds| now + chrono::Duration::seconds(seconds as i64)),
        refresh_token_expires_at: None,
        scope: Some(tokens.scopes.join(",")),
        id_token: tokens.id_token.clone(),
        password_hash: None,
        created_at: now,
        updated_at: now,
    };

    data.database.link_account(account).await?;

    Ok(user)
}
