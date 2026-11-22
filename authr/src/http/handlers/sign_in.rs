use actix_web::{HttpRequest, HttpResponse, http::header, web};
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::{
    core::{
        auth::AuthrContext,
        error::AuthrError,
        oauth::{
            OAuthProvider,
            types::{AuthorizationParams, OAuthTransaction},
            utils::{generate_pkce_challenge, get_provider_callback_url},
        },
        types::{Session, Verification},
        utils::generate_random_token,
    },
    database::store::AuthDatabase,
    http::cookie::build_session_cookie,
};

pub const VERIFICATION_PREFIX_OAUTH: &str = "oauth:";

// -------------------- Email and Password - POST "/sign-in/email" --------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInEmailRequest {
    email: String,
    password: String,
    #[serde(default = "default_remember_me")]
    remember_me: bool,
}

fn default_remember_me() -> bool {
    true
}

#[tracing::instrument(
    name = "auth.sign_in_email",
    skip_all,
    fields(remember_me = body.remember_me),
    err
)]
pub async fn sign_in_email<D: AuthDatabase + 'static>(
    req: HttpRequest,
    ctx: web::Data<AuthrContext<D>>,
    body: web::Json<SignInEmailRequest>,
) -> Result<HttpResponse, AuthrError> {
    let mut body = body.into_inner();
    body.email = body.email.trim().to_lowercase();

    // ----- Check request body
    if !ctx.is_email_valid(&body.email) {
        tracing::debug!("Email sign-in rejected due to invalid email");
        return Err(AuthrError::InvalidEmail);
    }
    if !ctx.is_password_vaild(&body.password) {
        tracing::debug!("Email sign-in rejected due to invalid password length");
        return Err(AuthrError::InvalidPassword);
    }

    // ----- Find the user
    let user = match ctx.store().find_user_by_email(&body.email).await? {
        Some(user) => user,
        None => {
            // Hash password to prevent timing attacks from revealing valid email addresses.
            if let Err(err) = ctx.hash_password(body.password).await {
                tracing::error!(
                    error = %err,
                    "Dummy password hashing failed"
                );
            }

            tracing::debug!("Email sign-in failed: user not found");
            return Err(AuthrError::InvalidCredentials);
        }
    };

    // ----- Find the credential account for the user
    let credential_account = match ctx
        .store()
        .find_account_by_provider("credential", &user.id.to_string())
        .await?
    {
        Some(account) => account,
        None => {
            if let Err(err) = ctx.hash_password(body.password).await {
                tracing::error!(
                    error = %err,
                    "Dummy password hashing failed"
                );
            }

            tracing::debug!("Email sign-in failed: credential account not found");
            return Err(AuthrError::InvalidCredentials);
        }
    };

    // ----- Check the received password
    let Some(password_hash) = credential_account.password_hash else {
        tracing::debug!("Email sign-in failed: credential account has no password hash");
        return Err(AuthrError::InvalidCredentials);
    };

    let valid_password = ctx.verify_password(body.password, password_hash).await?;

    if !valid_password {
        tracing::debug!("Email sign-in failed: password mismatch");
        return Err(AuthrError::InvalidCredentials);
    }

    // ----- Create the session
    let ip_address = req.peer_addr().map(|p| p.ip().to_string());
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|ua| ua.to_str().ok())
        .map(String::from);

    let session = ctx
        .store()
        .create_session(
            Session::new(user.id, ip_address, user_agent),
            body.remember_me,
        )
        .await?;

    tracing::info!("User signed in successfully");

    // ----- Give Response
    Ok(HttpResponse::Ok()
        .cookie(build_session_cookie(&session))
        .json(serde_json::json!({
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

// -------------------- OAuth2 - POST "/sign-in/social" --------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInSocialRequest {
    provider: String,
    callback_url: Option<String>,
    #[serde(default = "default_redirect")]
    disable_redirect: bool,
    scopes: Option<Vec<String>>,
}

fn default_redirect() -> bool {
    false
}

#[tracing::instrument(
    name = "auth.sign_in_social",
    skip_all,
    fields(
        provider = %body.provider,
        disable_redirect = body.disable_redirect,
        has_callback_url = body.callback_url.is_some(),
        has_custom_scopes = body.scopes.is_some()
    ),
    err
)]
pub async fn sign_in_social<D: AuthDatabase + 'static>(
    req: HttpRequest,
    ctx: web::Data<AuthrContext<D>>,
    body: web::Json<SignInSocialRequest>,
) -> Result<HttpResponse, AuthrError> {
    let body = body.into_inner();

    let config = ctx.config();

    // ----- Find the provider
    let Some(provider) = config.social_providers.get(&body.provider) else {
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
        callback_url: body.callback_url.clone(),
    };

    let transaction_value = serde_json::to_string(&transaction).map_err(|err| {
        tracing::error!(
            error = %err,
            "Failed to serialize OAuth transaction"
        );
        AuthrError::Internal
    })?;

    // ----- Build callback URL
    let redirect_uri =
        get_provider_callback_url(&config.base_url, &config.base_path, &req, provider.id())
            .map_err(|err| {
                tracing::error!(
                    error = %err,
                    "Failed to build OAuth callback URL"
                );
                err
            })?;

    // ----- Create a verification
    ctx.store()
        .create_verification(Verification::new(
            format!("{VERIFICATION_PREFIX_OAUTH}{state}"),
            transaction_value,
            Utc::now() + Duration::minutes(10),
        ))
        .await?;

    tracing::debug!("OAuth transaction stored successfully");

    // ----- Resolve scopes
    let scopes = body.scopes.unwrap_or_else(|| provider.scopes().to_vec());

    tracing::debug!(scope_count = scopes.len(), "Resolved OAuth scopes");

    // ----- Create authorization URL
    let authorization_url = provider
        .create_authorization_url(AuthorizationParams {
            state,
            code_challenge,
            redirect_uri,
            scopes,
        })
        .await
        .map_err(|err| {
            tracing::error!(
                error = %err,
                "Failed to create OAuth authorization URL"
            );
            err
        })?;

    tracing::info!(
        provider = %provider.id(),
        "OAuth authorization URL generated successfully"
    );

    // ----- Give Response
    let mut response = HttpResponse::Ok();

    if !body.disable_redirect {
        response.append_header(("Location", authorization_url.as_str()));
    }

    Ok(response.json(serde_json::json!({
        "url": authorization_url,
        "redirect": !body.disable_redirect,
    })))
}
