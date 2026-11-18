use actix_web::{HttpResponse, ResponseError, http::StatusCode, post, web};
use email_address::EmailAddress;
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

use crate::{
    core::{
        auth::AuthrData,
        types::{Account, User},
        utils::hash_password,
    },
    database::store::{AccountsStore, SessionsStore, UsersStore},
    http::utils::get_session_cookie,
};

// -------------------- Error --------------------
#[derive(Debug, Error)]
pub enum SignUpError {
    #[error("Invalid email")]
    InvalidEmail,
    #[error("Invalid name")]
    InvalidName,
    #[error("Invalid password")]
    InvalidPassword,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Finding user failed")]
    UserLookupFailed,
    #[error("Password hashing failed")]
    PasswordHashingFailed,
    #[error("User creation failed")]
    UserCreationFailed,
    #[error("Credential account creation failed")]
    AccountCreationFailed,
    #[error("Session creation failed")]
    SessionCreationFailed,
}

impl ResponseError for SignUpError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidEmail | Self::InvalidPassword => StatusCode::BAD_REQUEST,

            Self::UserAlreadyExists => StatusCode::CONFLICT,

            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(self.to_string())
    }
}

// -------------------- Handler --------------------
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterRequest {
    name: String,
    email: String,
    password: String,
    image: Option<String>,
    callback_url: Option<String>,
    #[serde(default = "default_remember_me")]
    remember_me: bool,
}
fn default_remember_me() -> bool {
    false
}

#[post("/sign-up")]
pub async fn sign_up(
    data: web::Data<AuthrData>,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, SignUpError> {
    let RegisterRequest {
        name,
        email,
        password,
        image,
        callback_url: _callback_url,
        remember_me,
    } = body.into_inner();
    let email = email.to_lowercase();

    // ---- Check request body
    if !EmailAddress::is_valid(&email) {
        return Err(SignUpError::InvalidEmail);
    }
    if password.len() < 8 || password.len() > 128 {
        return Err(SignUpError::InvalidPassword);
    }
    if name.trim().is_empty() {
        return Err(SignUpError::InvalidName);
    }

    // ---- Check if user already exists
    let db_user = data
        .database
        .find_user_by_email(&email)
        .await
        .map_err(|_| SignUpError::UserLookupFailed)?;
    if db_user.is_some() {
        return Err(SignUpError::UserAlreadyExists);
    }

    // ---- Create user
    let argon = data.argon.clone();
    let password_hash = web::block(move || {
        hash_password(&argon, &password).map_err(|_| SignUpError::PasswordHashingFailed)
    })
    .await
    .map_err(|_| SignUpError::PasswordHashingFailed)??;

    let created_user = data
        .database
        .create_user(User {
            name,
            email,
            image,
            ..Default::default()
        })
        .await
        .map_err(|_| SignUpError::UserCreationFailed)?;

    // ---- Link created user with a `credential` account
    data.database
        .link_account(Account {
            account_id: created_user.id.to_string(),
            provider_id: "credential".to_string(),
            user_id: created_user.id,
            password_hash: Some(password_hash),
            ..Default::default()
        })
        .await
        .map_err(|_| SignUpError::AccountCreationFailed)?;

    // ----- Create the session for the user
    let session = data
        .database
        .create_session(&created_user.id.to_string(), remember_me)
        .await
        .map_err(|_| SignUpError::SessionCreationFailed)?;

    // ----- Give Response
    Ok(HttpResponse::Created()
        .cookie(get_session_cookie(&session))
        .json(json!({
            "user": {
                "id": created_user.id,
                "name": created_user.name,
                "email": created_user.email,
                "image": created_user.image,
                "emailVerified": created_user.email_verified
            }
        })))
}
