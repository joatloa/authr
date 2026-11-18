use actix_web::{HttpResponse, post, web};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    core::{
        auth::AuthrData,
        error::AuthrError::{self},
        oauth::{
            OAuthProvider,
            types::AuthorizationParams,
            utils::{generate_pkce_challenge, get_provider_callback_url},
        },
        types::Verification,
        utils::{generate_random_value, hash_password, verify_password},
    },
    database::store::{AccountsStore, SessionsStore, UsersStore, VerificationStore},
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

    // ----- Find the user.
    let user = match data.database.find_user_by_email(&email).await? {
        Some(user) => user,
        None => {
            // Hash password to prevent timing attacks from revealing valid email addresses
            // By hashing passwords for invalid emails, we ensure consistent response times
            let _ = web::block(move || {
                let _ = hash_password(&data.argon, &password);
            })
            .await;

            return Err(AuthrError::InvalidCredentials);
        }
    };

    // ----- Find the `credential` account for the user
    let account = match data
        .database
        .find_account("credential", &user.id.to_string())
        .await?
    {
        Some(account) => account,
        None => {
            let _ = web::block(move || {
                let _ = hash_password(&data.argon, &password);
            })
            .await;

            return Err(AuthrError::InvalidCredentials);
        }
    };

    // ----- Check the received password against the `credential` account's password
    let Some(password_hash) = account.password_hash else {
        return Err(AuthrError::InvalidCredentials);
    };
    let valid_password = match web::block(move || verify_password(&password, &password_hash)).await
    {
        Ok(Ok(valid)) => valid,
        _ => {
            return Err(AuthrError::Internal);
        }
    };
    if !valid_password {
        return Err(AuthrError::InvalidCredentials);
    }

    // ----- Create the session for the user
    let session = data
        .database
        .create_session(&user.id.to_string(), remember_me)
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

#[post("/sign-in/social")]
pub async fn sign_in_social(
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
    let Some(provider) = data.providers.get(&provider) else {
        return Err(AuthrError::ProviderNotFound);
    };

    // ----- Build a transaction value for the transaction
    // Generate state and PKCE values.
    let state = generate_random_value();
    let code_verifier = generate_random_value();
    let code_challenge = generate_pkce_challenge(&code_verifier);

    // Save the OAuth transaction so the callback handler can retrieve
    // the code verifier and the frontend callback URL later.
    let transaction = OAuthTransaction {
        provider_id: provider.id().to_string(),
        code_verifier,
        callback_url: callback_url.clone(),
    };

    let transaction_value =
        serde_json::to_string(&transaction).map_err(|_| AuthrError::Internal)?;

    // ----- Create a verification
    let now = Utc::now();
    let verification = Verification {
        id: Uuid::new_v4(),
        identifier: format!("oauth:{state}"),
        value: transaction_value,
        expires_at: now + Duration::minutes(10),
        created_at: now,
        updated_at: now,
    };
    data.database.create_verification(verification).await?;

    // ----- Redirect to the OAuth provider
    // Build the callback URL registered with the OAuth provider.
    let redirect_uri = get_provider_callback_url(&data.base_url, provider.id())?;

    // Use custom scopes if provided; otherwise use the provider defaults.
    let scopes = scopes.clone().unwrap_or_else(|| provider.scopes().to_vec());

    let authorization_url = provider.authorization_url(AuthorizationParams {
        state,
        code_challenge,
        redirect_uri,
        scopes,
    })?;

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
