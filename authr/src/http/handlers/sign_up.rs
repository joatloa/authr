use actix_web::{HttpRequest, HttpResponse, http::header, post, web};
use email_address::EmailAddress;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    core::{
        auth::AuthrData,
        error::AuthrError,
        types::{Account, Session, User},
        utils::{generate_random_value, hash_password},
    },
    database::store::{AuthDatabase, UserQuery},
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
    req: HttpRequest,
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
    if password.len() < data.config.email_and_password.min_password_length
        || password.len() > data.config.email_and_password.max_password_length
    {
        return Err(AuthrError::InvalidPassword);
    }
    if name.trim().is_empty() {
        return Err(AuthrError::InvalidName);
    }

    // ---- Check if user already exists
    let db_user = data.database.find_user(UserQuery::Email(&email)).await?;
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
            id: Uuid::new_v4(),
            name,
            email,
            image,
            ..Default::default()
        })
        .await?;

    // ---- Link created user with a `credential` account
    data.database
        .create_account(Account {
            id: Uuid::new_v4(),
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
        .create_session(
            Session {
                id: Uuid::new_v4(),
                user_id: created_user.id,
                token: generate_random_value(),
                ip_address: req.peer_addr().map(|p| p.ip().to_string()),
                user_agent: req
                    .headers()
                    .get(header::USER_AGENT)
                    .and_then(|ua| ua.to_str().ok())
                    .map(String::from),
                ..Default::default()
            },
            remember_me,
        )
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
