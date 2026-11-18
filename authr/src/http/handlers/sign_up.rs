use actix_web::{HttpResponse, post, web};
use email_address::EmailAddress;
use serde::Deserialize;
use serde_json::json;

use crate::{
    core::{
        auth::AuthrData,
        error::AuthrError,
        types::{Account, User},
        utils::hash_password,
    },
    database::store::{AccountsStore, SessionsStore, UsersStore},
    http::utils::get_session_cookie,
};

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
) -> Result<HttpResponse, AuthrError> {
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
        return Err(AuthrError::InvalidEmail);
    }
    if password.len() < 8 || password.len() > 128 {
        return Err(AuthrError::InvalidPassword);
    }
    if name.trim().is_empty() {
        return Err(AuthrError::InvalidName);
    }

    // ---- Check if user already exists
    let db_user = data.database.find_user_by_email(&email).await?;
    if db_user.is_some() {
        return Err(AuthrError::UserAlreadyExists);
    }

    // ---- Create user
    let argon = data.argon.clone();
    let password_hash = web::block(move || hash_password(&argon, &password))
        .await
        .map_err(|_| AuthrError::PasswordHashingFailed)??;

    let created_user = data
        .database
        .create_user(User {
            name,
            email,
            image,
            ..Default::default()
        })
        .await?;

    // ---- Link created user with a `credential` account
    data.database
        .link_account(Account {
            account_id: created_user.id.to_string(),
            provider_id: "credential".to_string(),
            user_id: created_user.id,
            password_hash: Some(password_hash),
            ..Default::default()
        })
        .await?;

    // ----- Create the session for the user
    let session = data
        .database
        .create_session(&created_user.id.to_string(), remember_me)
        .await?;

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
