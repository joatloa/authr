use actix_web::{HttpRequest, HttpResponse, http::header, web};
use serde::Deserialize;
use serde_json::json;

use crate::{
    core::{
        auth::AuthrContext,
        error::AuthrError,
        types::{Account, Session, User},
    },
    database::store::AuthDatabase,
    http::cookie::build_session_cookie,
};

// -------------------- Sign Up - POST "/sign-up" --------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpRequest {
    /// The name of the user
    name: String,
    /// The email of the user
    email: String,
    /// The password of the user
    password: String,
    /// The profile image URL of the user
    image: Option<String>,
    #[serde(default)]
    /// If this is false, the session will not be remembered. Default is `false`.
    remember_me: bool,
}

#[tracing::instrument(
    name = "auth.sign_up",
    skip_all,
    fields(
        remember_me = body.remember_me,
        auto_sign_in = ctx.config().email_and_password.auto_sign_in
    ),
    err
)]
pub async fn sign_up<D: AuthDatabase + 'static>(
    req: HttpRequest,
    ctx: web::Data<AuthrContext<D>>,
    body: web::Json<SignUpRequest>,
) -> Result<HttpResponse, AuthrError> {
    let mut body = body.into_inner();
    body.email = body.email.trim().to_lowercase();

    let config = ctx.config();

    let should_return_generic_duplicate_response = !config.email_and_password.auto_sign_in;
    let should_skip_auto_sign_in = !config.email_and_password.auto_sign_in;

    // ----- Check request body
    if !ctx.is_email_valid(&body.email) {
        tracing::debug!("Registration rejected: invalid email");
        return Err(AuthrError::InvalidEmail);
    }
    if !ctx.is_password_vaild(&body.password) {
        tracing::debug!("Registration rejected: invalid password length");
        return Err(AuthrError::InvalidPassword);
    }
    if !ctx.is_name_valid(&body.name) {
        tracing::debug!("Registration rejected: empty name");
        return Err(AuthrError::InvalidName);
    }

    // ----- Check if user already exists
    let db_user = ctx.store().find_user_by_email(&body.email).await?;

    if db_user.is_some() {
        tracing::warn!(
            generic_response = should_return_generic_duplicate_response,
            "Registration attempted with an existing email"
        );

        if should_return_generic_duplicate_response {
            return Ok(build_generic_duplicate_response(
                ctx,
                body.name,
                body.email,
                body.password,
                body.image,
            )
            .await);
        }

        return Err(AuthrError::UserAlreadyExists);
    }

    // ----- Create user
    let password_hash = ctx.hash_password(body.password.clone()).await?;

    let created_user = match ctx
        .store()
        .create_user(User::new(
            body.name.clone(),
            body.email.clone(),
            false,
            body.image.clone(),
        ))
        .await
    {
        Ok(user) => {
            tracing::info!(user_id = %user.id, "User registered successfully");
            user
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                "Failed to create user"
            );

            if should_return_generic_duplicate_response {
                return Ok(build_generic_duplicate_response(
                    ctx,
                    body.name,
                    body.email,
                    body.password,
                    body.image,
                )
                .await);
            }

            return Err(err);
        }
    };

    // ----- Link created user with a credential account
    if let Err(error) = ctx
        .store()
        .create_account(Account::new_credential(created_user.id, password_hash))
        .await
    {
        tracing::error!(
            user_id = %created_user.id,
            error = %error,
            "Failed to create credential account"
        );

        return Err(error);
    }

    tracing::debug!(
        user_id = %created_user.id,
        "Credential account created successfully"
    );

    // ----- Skip automatic sign-in
    if should_skip_auto_sign_in {
        tracing::info!(
            user_id = %created_user.id,
            "Registration completed without automatic sign-in"
        );

        return Ok(HttpResponse::Created().json(json!({
            "token": null,
            "user": {
                "id": created_user.id,
                "name": created_user.name,
                "email": created_user.email,
                "image": created_user.image,
                "emailVerified": created_user.email_verified
            }
        })));
    }

    // ----- Create session
    let ip_address = req.peer_addr().map(|p| p.ip().to_string());
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|ua| ua.to_str().ok())
        .map(String::from);

    let session = match ctx
        .store()
        .create_session(
            Session::new(created_user.id, ip_address, user_agent),
            body.remember_me,
        )
        .await
    {
        Ok(session) => {
            tracing::debug!(
                user_id = %created_user.id,
                session_id = %session.id,
                "Session created successfully"
            );
            session
        }
        Err(error) => {
            tracing::error!(
                user_id = %created_user.id,
                error = %error,
                "Failed to create session after registration"
            );

            return Err(error);
        }
    };

    // ----- Give response
    tracing::info!(
        user_id = %created_user.id,
        "Registration completed successfully"
    );

    Ok(HttpResponse::Created()
        .cookie(build_session_cookie(&session))
        .json(json!({
            "token": session.token,
            "user": {
                "id": created_user.id,
                "name": created_user.name,
                "email": created_user.email,
                "image": created_user.image,
                "emailVerified": created_user.email_verified
            }
        })))
}

// -------------------- Helpers --------------------

async fn build_generic_duplicate_response<D: AuthDatabase + 'static>(
    ctx: web::Data<AuthrContext<D>>,
    name: String,
    email: String,
    password: String,
    image: Option<String>,
) -> HttpResponse {
    if let Err(err) = ctx.hash_password(password).await {
        tracing::error!(
            error = %err,
            "Dummy password hashing failed"
        );
    }

    tracing::debug!("Returning generic registration response");

    let synthetic_user = User::new(name, email, false, image);

    HttpResponse::Created().json(json!({
        "token": null,
        "user": {
            "id": synthetic_user.id,
            "name": synthetic_user.name,
            "email": synthetic_user.email,
            "image": synthetic_user.image,
            "emailVerified": synthetic_user.email_verified
        }
    }))
}
