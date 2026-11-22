use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use url::Url;

use crate::{
    core::{
        auth::AuthrContext, error::AuthrError, types::Verification, utils::generate_random_token,
    },
    database::store::AuthDatabase,
    http::middleware::session::AuthenticatedSession,
};

// -------------------- Constants --------------------

const VERIFICATION_PREFIX_RESET_PASSWORD: &str = "reset-password:";

// -------------------- Request Password Reset - POST "/request-password-reset" --------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPasswordReset {
    /// The email address of the user to send a password reset email to.
    pub email: String,
    /// The URL to redirect the user to reset their password.
    /// If the token isn't valid or expired, it'll be redirected with a query parameter `?error=INVALID_TOKEN`.
    /// If the token is valid, it'll be redirected with a query parameter `?token=VALID_TOKEN`.
    pub redirect_to: Option<String>,
}

#[tracing::instrument(name = "auth.request_password_reset", skip_all)]
/// Creates a reset token and passes the reset link to the configured sender.
pub async fn request_password_reset<D: AuthDatabase + 'static>(
    req: HttpRequest,
    ctx: web::Data<AuthrContext<D>>,
    body: web::Json<RequestPasswordReset>,
) -> Result<HttpResponse, AuthrError> {
    let RequestPasswordReset { email, redirect_to } = body.into_inner();

    let config = ctx.config();
    let sender = match config.email_and_password.reset_password_sender.as_ref() {
        Some(sender) => sender,
        None => {
            tracing::error!(
                "Password Reset: Reset password isn't enabled. Please pass a `PasswordResetSender` in your auth config!"
            );
            return Err(AuthrError::PasswordResetDisabled);
        }
    };

    // ----- Check request body
    let email = email.trim().to_lowercase();
    if !email_address::EmailAddress::is_valid(&email) {
        tracing::warn!("Password Reset: Invalid email address");
        return Err(AuthrError::InvalidEmail);
    }

    if let Some(redirect_to) = redirect_to.as_deref() {
        if !config.base_url.is_allowed(redirect_to) {
            tracing::warn!("Password Reset: Callback URL isn't allowed");
            return Err(AuthrError::InvalidCallbackUrl);
        }
    }

    // ----- Create reset token
    if let Some(user) = ctx.store().find_user_by_email(&email).await? {
        let verification_token = generate_random_token();
        let identifier = format!("{VERIFICATION_PREFIX_RESET_PASSWORD}{verification_token}");

        ctx.store()
            .create_verification(Verification::new(
                identifier,
                user.id.to_string(),
                Utc::now() + chrono::Duration::hours(1),
            ))
            .await?;

        // ----- Build reset URL
        let connection = req.connection_info();

        let mut reset_url = config
            .base_url
            .resolve(Some(connection.host()), Some(connection.scheme()))?;

        reset_url.set_path(&format!(
            "{}/reset-password/{}",
            config.base_path, verification_token
        ));

        reset_url
            .query_pairs_mut()
            .append_pair("callbackURL", &redirect_to.unwrap_or(String::new()));

        // ----- Send reset email
        sender
            .send_reset_password(user, reset_url.into(), verification_token)
            .await
            .map_err(|error| {
                tracing::error!(
                    error = %error,
                    "Password Reset: Failed to send reset email"
                );
                error
            })?;

        tracing::info!("Password Reset: Reset email sent successfully");
    } else {
        // We simulate the verification token generation and the database lookup
        // to mitigate timing attacks.

        generate_random_token();

        ctx.store()
            .find_verification_by_identifier("dummy-reset-password-token")
            .await?;

        tracing::debug!("Password Reset: User not found");
    }

    Ok(HttpResponse::Ok().json(json!({
        "status": true,
        "message": "If this email exists in our system, check your email for the reset link"
    })))
}
// -------------------- Reset Password Callback - GET "/reset-password/{token}" --------------------

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    /// The URL to redirect the user to reset their password
    #[serde(rename = "callbackURL")]
    pub callback_url: String,
}

#[tracing::instrument(name = "auth.reset_password_callback", skip_all)]
/// Validates a reset token and redirects to the supplied callback with the token.
pub async fn reset_password_callback<D: AuthDatabase + 'static>(
    ctx: web::Data<AuthrContext<D>>,
    path: web::Path<String>,
    query: web::Query<CallbackQuery>,
) -> Result<HttpResponse, AuthrError> {
    // The token to reset the password
    let verification_token = path.into_inner();

    let CallbackQuery { callback_url } = query.into_inner();

    // ----- Parse callback URL
    let mut callback = parse_callback_url(&callback_url)?;

    // ----- Validate reset token
    let identifier = format!("{VERIFICATION_PREFIX_RESET_PASSWORD}{verification_token}");

    let is_valid = ctx
        .store()
        .find_verification_by_identifier(&identifier)
        .await?
        .is_some_and(|verification| verification.expires_at > Utc::now());

    if is_valid {
        callback
            .query_pairs_mut()
            .append_pair("token", &verification_token);
        tracing::debug!("Password Reset: Reset token validated");
    } else {
        callback
            .query_pairs_mut()
            .append_pair("error", "INVALID_TOKEN");

        tracing::warn!("Password Reset: Invalid or expired reset token");
    }

    // ----- Redirect to callback
    Ok(HttpResponse::Found()
        .append_header((actix_web::http::header::LOCATION, callback.as_str()))
        .finish())
}

// -------------------- Reset Password - POST "/reset-password" --------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordRequest {
    /// The new password to set
    pub new_password: String,
    /// The token to reset the password
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordQuery {
    pub token: Option<String>,
}

#[tracing::instrument(name = "auth.reset_password", skip_all)]
/// Replaces the password associated with a valid, unexpired reset token.
pub async fn reset_password<D: AuthDatabase + 'static>(
    ctx: web::Data<AuthrContext<D>>,
    query: Option<web::Query<ResetPasswordQuery>>,
    body: web::Json<ResetPasswordRequest>,
) -> Result<HttpResponse, AuthrError> {
    let body = body.into_inner();
    let query = query.map(|query| query.into_inner());

    let verification_token = body
        .token
        .or_else(|| query.and_then(|query| query.token))
        .ok_or_else(|| {
            tracing::warn!("Password Reset: Missing reset token");
            AuthrError::InvalidResetToken
        })?;

    // ----- Check password policy
    if !ctx.is_password_vaild(&body.new_password) {
        tracing::warn!("Password Reset: New password doesn't meet the password policy");
        return Err(AuthrError::InvalidPassword);
    }

    // ----- Validate reset token
    let identifier = format!("{VERIFICATION_PREFIX_RESET_PASSWORD}{verification_token}");

    let verification = ctx
        .store()
        .find_verification_by_identifier(&identifier)
        .await?
        .filter(|verification| verification.expires_at > Utc::now())
        .ok_or_else(|| {
            tracing::warn!("Password Reset: Invalid or expired reset token");
            AuthrError::InvalidResetToken
        })?;

    // ----- Find user credentials
    let user = ctx
        .store()
        .find_user_by_id(&verification.value)
        .await?
        .ok_or_else(|| {
            tracing::warn!("Password Reset: User associated with reset token wasn't found");
            AuthrError::UserNotFound
        })?;

    let mut credential = ctx
        .store()
        .find_account_by_provider("credential", &user.id.to_string())
        .await?
        .ok_or_else(|| {
            tracing::warn!("Password Reset: Credential account wasn't found");
            AuthrError::InvalidCredentials
        })?;

    // ----- Update password
    // Hash before consuming the token so password hashing failures leave it usable.
    let password_hash = ctx.hash_password(body.new_password).await?;

    // Atomic consumption makes a reset link single use when requests race.
    let consumed = ctx.store().consume_verification(&identifier).await?;
    if consumed.is_none_or(|verification| verification.expires_at <= Utc::now()) {
        tracing::warn!("Password Reset: Reset token was already consumed or expired");
        return Err(AuthrError::InvalidResetToken);
    }

    credential.password_hash = Some(password_hash);

    ctx.store()
        .update_account(credential)
        .await?
        .ok_or(AuthrError::InvalidCredentials)?;

    // ----- Revoke existing sessions
    ctx.store()
        .delete_user_sessions(&user.id.to_string())
        .await?;

    tracing::info!("Password Reset: Password updated successfully");

    Ok(HttpResponse::Ok().json(json!({ "status": true })))
}

// -------------------- Verify Password - POST "/verify-password" --------------------

#[derive(Debug, Deserialize)]
pub struct VerifyPasswordRequest {
    pub password: String,
}

#[tracing::instrument(name = "auth.verify_password", skip_all)]
/// Verifies the authenticated user's current password.
pub async fn verify_password<D: AuthDatabase + 'static>(
    req: HttpRequest,
    ctx: web::Data<AuthrContext<D>>,
    body: web::Json<VerifyPasswordRequest>,
) -> Result<HttpResponse, AuthrError> {
    let body = body.into_inner();

    // ----- Find authenticated user
    let authenticated = req
        .extensions()
        .get::<AuthenticatedSession>()
        .cloned()
        .ok_or_else(|| {
            tracing::warn!("Verify Password: No authenticated session found");
            AuthrError::InvalidCredentials
        })?;

    // ----- Verify password
    let credential = ctx
        .store()
        .find_account_by_provider("credential", &authenticated.user.id.to_string())
        .await?
        .ok_or_else(|| {
            tracing::warn!("Verify Password: Credential account wasn't found");
            AuthrError::InvalidCredentials
        })?;

    let password_hash = credential.password_hash.ok_or_else(|| {
        tracing::warn!("Verify Password: Account doesn't have a password hash");
        AuthrError::InvalidCredentials
    })?;

    if !ctx.verify_password(body.password, password_hash).await? {
        tracing::warn!("Verify Password: Password verification failed");
        return Err(AuthrError::InvalidPassword);
    }

    tracing::debug!("Verify Password: Password verified successfully");

    Ok(HttpResponse::Ok().json(json!({ "status": true })))
}

// -------------------- Helpers --------------------

/// Parses and validates an HTTP or HTTPS callback URL.
fn parse_callback_url(value: &str) -> Result<Url, AuthrError> {
    let url = Url::parse(value).map_err(|_| AuthrError::InvalidCallbackUrl)?;

    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(AuthrError::InvalidCallbackUrl);
    }

    Ok(url)
}
