use actix_web::{HttpRequest, HttpResponse, http::header, web};
use email_address::EmailAddress;
use serde::Deserialize;
use serde_json::json;

use crate::{
    core::{
        auth::AuthrData,
        error::AuthrError,
        types::{Account, Session, User},
        utils::hash_password_async,
    },
    database::store::{AuthDatabase, UserQuery},
    http::utils::get_session_cookie,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
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
        auto_sign_in = data.config.email_and_password.auto_sign_in
    ),
    err
)]
pub async fn sign_up<D: AuthDatabase + 'static>(
    req: HttpRequest,
    data: web::Data<AuthrData<D>>,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, AuthrError> {
    let RegisterRequest {
        name,
        email,
        password,
        image,
        remember_me,
    } = body.into_inner();

    let email = email.trim().to_lowercase();

    let should_return_generic_duplicate_response = !data.config.email_and_password.auto_sign_in;
    let should_skip_auto_sign_in = !data.config.email_and_password.auto_sign_in;

    // ----- Check request body
    if !EmailAddress::is_valid(&email) {
        tracing::debug!("Registration rejected: invalid email");
        return Err(AuthrError::InvalidEmail);
    }

    if password.len() < data.config.email_and_password.min_password_length
        || password.len() > data.config.email_and_password.max_password_length
    {
        tracing::debug!("Registration rejected: invalid password length");
        return Err(AuthrError::InvalidPassword);
    }

    if name.trim().is_empty() {
        tracing::debug!("Registration rejected: empty name");
        return Err(AuthrError::InvalidName);
    }

    // ----- Check if user already exists
    let db_user = data.database.find_user(UserQuery::Email(&email)).await?;

    if db_user.is_some() {
        tracing::warn!(
            generic_response = should_return_generic_duplicate_response,
            "Registration attempted with an existing email"
        );

        if should_return_generic_duplicate_response {
            return Ok(build_generic_duplicate_response(data, name, email, password, image).await);
        }

        return Err(AuthrError::UserAlreadyExists);
    }

    // ----- Create user
    let password_hash = hash_password_async(data.argon.clone(), password.clone()).await?;

    let created_user = match data
        .database
        .create_user(User::new(name.clone(), email.clone(), false, image.clone()))
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
                return Ok(
                    build_generic_duplicate_response(data, name, email, password, image).await,
                );
            }

            return Err(err);
        }
    };

    // ----- Link created user with a credential account
    if let Err(error) = data
        .database
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

    let session = match data
        .database
        .create_session(
            Session::new(created_user.id, ip_address, user_agent),
            remember_me,
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
        .cookie(get_session_cookie(&session))
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

// ----- Generic duplicate response

async fn build_generic_duplicate_response<D: AuthDatabase + 'static>(
    data: web::Data<AuthrData<D>>,
    name: String,
    email: String,
    password: String,
    image: Option<String>,
) -> HttpResponse {
    if let Err(err) = hash_password_async(data.argon.clone(), password).await {
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
