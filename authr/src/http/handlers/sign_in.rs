use actix_web::{HttpRequest, HttpResponse, http::header, post, web};
use email_address::EmailAddress;
use serde::{Deserialize, Serialize};

use crate::{
    core::{
        auth::AuthrData,
        error::AuthrError::{self},
        oauth::{
            OAuthProvider,
            types::AuthorizationParams,
            utils::{generate_pkce_challenge, get_provider_callback_url},
        },
        types::{Session, Verification},
        utils::{generate_random_token, hash_password_async, verify_password_async},
    },
    database::store::{AccountQuery, AuthDatabase, UserQuery},
    http::utils::get_session_cookie,
};

// -------------------- Email and Password --------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigninEmailRequest {
    email: String,
    password: String,
    #[serde(default = "default_remember_me")]
    remember_me: bool,
    callback_url: Option<String>,
}

fn default_remember_me() -> bool {
    true
}

#[post("/sign-in/email")]
pub async fn sign_in_email(
    req: HttpRequest,
    data: web::Data<AuthrData>,
    body: web::Json<SigninEmailRequest>,
) -> Result<HttpResponse, AuthrError> {
    let SigninEmailRequest {
        email,
        password,
        remember_me,
        callback_url,
    } = body.into_inner();
    let email = email.trim().to_lowercase();

    // ----- Check request body
    if !EmailAddress::is_valid(&email) {
        return Err(AuthrError::InvalidEmail);
    }
    if password.len() < data.config.email_and_password.min_password_length
        || password.len() > data.config.email_and_password.max_password_length
    {
        return Err(AuthrError::InvalidPassword);
    }

    // ----- Find the user.
    let user = match data.database.find_user(UserQuery::Email(&email)).await? {
        Some(user) => user,
        None => {
            // Hash password to prevent timing attacks from revealing valid email addresses
            // By hashing passwords for invalid emails, we ensure consistent response times
            if let Err(err) = hash_password_async(data.argon.clone(), password).await {
                tracing::error!(
                    error = %err,
                    "Dummy password hashing failed"
                );
            }

            return Err(AuthrError::InvalidCredentials);
        }
    };

    // ----- Find the `credential` account for the user
    let credential_account = match data
        .database
        .find_account(AccountQuery::Provider {
            provider_id: "credential",
            account_id: &user.id.to_string(),
        })
        .await?
    {
        Some(account) => account,
        None => {
            if let Err(err) = hash_password_async(data.argon.clone(), password).await {
                tracing::error!(
                    error = %err,
                    "Dummy password hashing failed"
                );
            }

            return Err(AuthrError::InvalidCredentials);
        }
    };

    // ----- Check the received password against the `credential` account's password
    let password_hash = credential_account
        .password_hash
        .ok_or(AuthrError::InvalidCredentials)?;
    let valid_password = verify_password_async(password, password_hash).await?;
    if !valid_password {
        return Err(AuthrError::InvalidCredentials);
    }

    // ----- Create the session for the user
    let ip_address = req.peer_addr().map(|p| p.ip().to_string());
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|ua| ua.to_str().ok())
        .map(String::from);
    let session = data
        .database
        .create_session(Session::new(user.id, ip_address, user_agent), remember_me)
        .await?;

    // ----- Give Response
    Ok(HttpResponse::Ok()
        .cookie(get_session_cookie(&session))
        .json(serde_json::json!({
            "redirect": callback_url.is_some(),
            "url": callback_url,
            "token": session.token,
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "emailVerified": user.email_verified,
                "image": user.image,
            }
        })))
}

// -------------------- OAuth2 --------------------
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigninSocialRequest {
    provider: String,
    callback_url: Option<String>,
    #[serde(default = "default_redirect")]
    redirect: bool,
    scopes: Option<Vec<String>>,
}
fn default_redirect() -> bool {
    false
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OAuthTransaction {
    provider_id: String,
    code_verifier: String,
    callback_url: Option<String>,
}

#[tracing::instrument(
    name = "auth.sign_in_social",
    skip_all,
    fields(
        provider = %body.provider,
        redirect = body.redirect
    ),
    err
)]
#[post("/sign-in/social")]
pub async fn sign_in_social(
    req: HttpRequest,
    data: web::Data<AuthrData>,
    body: web::Json<SigninSocialRequest>,
) -> Result<HttpResponse, AuthrError> {
    let SigninSocialRequest {
        provider,
        callback_url,
        redirect,
        scopes,
    } = body.into_inner();

    // ----- Find the provider
    let Some(provider) = data.config.social_providers.get(&provider) else {
        tracing::warn!("Social sign-in requested with an unsupported provider");
        return Err(AuthrError::ProviderNotFound);
    };

    // ----- Build values for OAuth
    let state = generate_random_token();
    let code_verifier = generate_random_token();
    let code_challenge = generate_pkce_challenge(&code_verifier);

    // Save the OAuth transaction so the callback handler can retrieve
    // the code verifier and the frontend callback URL later.
    let transaction = OAuthTransaction {
        provider_id: provider.id().to_string(),
        code_verifier,
        callback_url: callback_url.clone(),
    };

    let transaction_value = serde_json::to_string(&transaction).map_err(|err| {
        tracing::error!(
            error = %err,
            "Failed to serialize OAuth transaction"
        );
        AuthrError::Internal
    })?;

    // ----- Create a verification
    data.database
        .create_verification(Verification::new(
            format!("oauth:{state}"),
            transaction_value,
        ))
        .await?;

    // ----- Build callback URL
    let redirect_uri = get_provider_callback_url(
        &data.config.base_url,
        &data.config.base_path,
        &req,
        provider.id(),
    )?;

    // ----- Resolve scopes
    let scopes = scopes.unwrap_or_else(|| provider.scopes().to_vec());

    // ----- Create authorization URL
    let authorization_url = provider
        .create_authorization_url(AuthorizationParams {
            state,
            code_challenge,
            redirect_uri,
            scopes,
        })
        .await?;

    // ----- Give Response
    let mut response = HttpResponse::Ok();

    if redirect {
        response.append_header(("Location", authorization_url.as_str()));
    }

    Ok(response.json(serde_json::json!({
        "url": authorization_url,
        "redirect": redirect,
    })))
}
