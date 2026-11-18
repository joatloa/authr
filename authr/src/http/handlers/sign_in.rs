use actix_web::{HttpResponse, Responder, post, web};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    core::{
        auth::AuthrData,
        oauth::{
            OAuthProvider,
            types::AuthorizationParams,
            utils::{generate_pkce_challenge, get_provider_callback_url},
        },
        types::Verification,
        utils::{create_argon, generate_random_value, hash_password, verify_password},
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
) -> impl Responder {
    let SigninEmailRequest {
        email,
        password,
        remember_me,
        callback_url,
    } = body.into_inner();
    let email = email.trim().to_lowercase();

    // ----- Find the user.
    let user = match data.database.find_user_by_email(&email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            // Hash password to prevent timing attacks from revealing valid email addresses
            // By hashing passwords for invalid emails, we ensure consistent response times
            let _ = web::block(move || {
                let _ = hash_password(&data.argon, &password);
            })
            .await;

            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid email or password"
            }));
        }
        Err(error) => {
            eprintln!("Failed to find user: {error}");
            return HttpResponse::InternalServerError().finish();
        }
    };

    // ----- Find the `credential` account for the user
    let account = match data
        .database
        .find_account("credential", &user.id.to_string())
        .await
    {
        Ok(Some(account)) => account,
        Ok(None) => {
            let _ = web::block(move || {
                let argon = create_argon();
                let _ = hash_password(&argon, &password);
            })
            .await;

            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid email or password"
            }));
        }
        Err(error) => {
            eprintln!("Failed to find credential account: {error}");
            return HttpResponse::InternalServerError().finish();
        }
    };

    // ----- Check the received password against the `credential` account's password
    let Some(password_hash) = account.password_hash else {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid email or password"
        }));
    };

    let valid_password = match web::block(move || verify_password(&password, &password_hash)).await
    {
        Ok(Ok(valid)) => valid,
        _ => {
            return HttpResponse::InternalServerError().finish();
        }
    };

    if !valid_password {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid email or password"
        }));
    }

    // ----- Create the session for the user
    let session = match data
        .database
        .create_session(&user.id.to_string(), remember_me)
        .await
    {
        Ok(session) => session,
        Err(error) => {
            eprintln!("Failed to create session: {error}");
            return HttpResponse::InternalServerError().finish();
        }
    };

    // ----- Give Response
    HttpResponse::Ok()
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
        }))
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
) -> impl Responder {
    let SigninSocialRequest {
        provider,
        callback_url,
        redirect,
        scopes,
    } = body.into_inner();

    // ----- Find the provider
    let Some(provider) = data.providers.get(&provider) else {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "OAuth provider not found"
        }));
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

    let transaction_value = match serde_json::to_string(&transaction) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Failed to serialize OAuth transaction: {error}");
            return HttpResponse::InternalServerError().finish();
        }
    };

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
    if let Err(error) = data.database.create_verification(verification).await {
        eprintln!("Failed to store OAuth transaction: {error}");
        return HttpResponse::InternalServerError().finish();
    }

    // ----- Redirect to the OAuth provider
    // Build the callback URL registered with the OAuth provider.
    let redirect_uri = match get_provider_callback_url(&data.base_url, provider.id()) {
        Ok(url) => url,
        Err(error) => {
            eprintln!("Invalid OAuth callback URL: {error}");
            return HttpResponse::InternalServerError().finish();
        }
    };

    // Use custom scopes if provided; otherwise use the provider defaults.
    let scopes = scopes.clone().unwrap_or_else(|| provider.scopes().to_vec());

    let authorization_url = match provider.authorization_url(AuthorizationParams {
        state,
        code_challenge,
        redirect_uri,
        scopes,
    }) {
        Ok(url) => url,
        Err(error) => {
            eprintln!("Failed to generate authorization URL: {error}");
            return HttpResponse::InternalServerError().finish();
        }
    };

    // ----- Give Response
    let mut response = HttpResponse::Ok();

    if redirect {
        response.append_header(("Location", authorization_url.as_str()));
    }

    response.json(serde_json::json!({
        "url": authorization_url,
        "redirect": redirect,
    }))
}
