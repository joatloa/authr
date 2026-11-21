use actix_web::{App, http::StatusCode, test, web};
use chrono::Duration;
use serde_json::{Value, json};

use authr::{
    core::auth::{AuthrContext, SocialProviders},
    database::store::{AccountFilter, AuthDatabase, SessionFilter, UserFilter},
    http::router,
};

use crate::common::{TestDatabase, config, init_tracing, sign_up_user, test_app};

// -------------------- Successful Registration --------------------

#[actix_web::test]
async fn sign_up_creates_user_account_and_session() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let req_body = json!({
        "name": "Test User",
        "email": "test@example.com",
        "password": "password123"
    });
    let response = sign_up_user!(app, req_body.clone());

    assert_eq!(response.status(), StatusCode::CREATED);

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;

    assert!(!body["token"].as_str().unwrap_or_default().is_empty());
    assert_eq!(body["user"]["name"], req_body["name"]);
    assert_eq!(body["user"]["email"], req_body["email"]);
    assert_eq!(body["user"]["image"], Value::Null);
    assert_eq!(body["user"]["emailVerified"], false);

    let user_id = body["user"]["id"].as_str().unwrap();

    // ----- Check User from Database
    let user = database
        .find_user(UserFilter::Id(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(user.name, req_body["name"]);
    assert_eq!(user.email, req_body["email"]);

    // ----- Check Account from Database
    let account = database
        .find_account(AccountFilter::UserId(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(account.provider_id, "credential");
    assert!(account.password_hash.is_some());

    // ----- Check Session from Database
    let session = database
        .find_session(SessionFilter::UserId(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(session.user_id, user.id);
}

// -------------------- Email Normalization --------------------

#[actix_web::test]
async fn sign_up_normalizes_email_to_lowercase() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let req_body = json!({
        "name": "Test User",
        "email": "TEST@EXAMPLE.COM",
        "password": "password123"
    });
    let response = sign_up_user!(app, req_body);

    assert_eq!(response.status(), StatusCode::CREATED);

    // ----- Check User from Database
    let user = database
        .find_user(UserFilter::Email("test@example.com"))
        .await
        .unwrap();

    assert!(user.is_some());
}

// -------------------- Duplicate Email --------------------

#[actix_web::test]
async fn sign_up_returns_generic_response_for_existing_email() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(false, SocialProviders::new(vec![])));

    let req_body = json!({
        "name": "Test User",
        "email": "test@example.com",
        "password": "password123"
    });

    // First Sign-Up
    let first_response = sign_up_user!(app, req_body.clone());
    assert_eq!(first_response.status(), StatusCode::CREATED);

    let first_body: Value = test::read_body_json(first_response).await;
    let first_user_id = first_body["user"]["id"].as_str().unwrap();

    // Duplicate Sign-Up
    let second_response = sign_up_user!(app, req_body);
    assert_eq!(second_response.status(), StatusCode::CREATED);

    let second_body: Value = test::read_body_json(second_response).await;

    assert!(second_body["token"].is_null());

    let second_user_id = second_body["user"]["id"].as_str().unwrap();
    assert_ne!(first_user_id, second_user_id);

    // ----- Check only first user exists in database
    let existing_user = database
        .find_user(UserFilter::Id(first_user_id))
        .await
        .unwrap();

    let synthetic_user = database
        .find_user(UserFilter::Id(second_user_id))
        .await
        .unwrap();

    assert!(existing_user.is_some());
    assert!(synthetic_user.is_none());
}

// -------------------- Validation --------------------

#[actix_web::test]
async fn sign_up_rejects_invalid_email() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let req_body = json!({
        "name": "Test User",
        "email": "invalid-email",
        "password": "password123"
    });
    let response = sign_up_user!(app, req_body);

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn sign_up_rejects_short_password() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let req_body = json!({
        "name": "John Doe",
        "email": "john@example.com",
        "password": "short"
    });
    let response = sign_up_user!(app, req_body);

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn sign_up_rejects_long_password() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let req_body = json!({
        "name": "Test User",
        "email": "john@example.com",
        "password": "a".repeat(129)
    });
    let response = sign_up_user!(app, req_body);

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn sign_up_rejects_empty_name() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let req_body = json!({
        "name": "   ",
        "email": "john@example.com",
        "password": "password123"
    });
    let response = sign_up_user!(app, req_body);

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn sign_up_rejects_missing_fields() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let req_body = json!({
        "email": "john@example.com",
        "password": "password123"
    });
    let response = sign_up_user!(app, req_body);

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -------------------- Remember Me --------------------

#[actix_web::test]
async fn sign_up_creates_long_lived_session_when_remember_me_is_true() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let req_body = json!({
        "name": "Test User",
        "email": "john@example.com",
        "password": "password123",
        "rememberMe": true
    });
    let response = sign_up_user!(app, req_body);

    assert_eq!(response.status(), StatusCode::CREATED);

    // ----- Check Session from Dataabse
    let body: Value = test::read_body_json(response).await;
    let user_id = body["user"]["id"].as_str().unwrap();

    let session = database
        .find_session(SessionFilter::UserId(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(session.expires_at - session.created_at, Duration::days(30));
}

#[actix_web::test]
async fn sign_up_creates_short_lived_session_when_remember_me_is_false() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let req_body = json!({
        "name": "Test User",
        "email": "john@example.com",
        "password": "password123",
        "rememberMe": false
    });
    let response = sign_up_user!(app, req_body);

    assert_eq!(response.status(), StatusCode::CREATED);

    // ----- Check Session from Dataabse
    let body: Value = test::read_body_json(response).await;
    let user_id = body["user"]["id"].as_str().unwrap();

    let session = database
        .find_session(SessionFilter::UserId(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(session.expires_at - session.created_at, Duration::days(1));
}

// -------------------- Automatic Sign-In --------------------

#[actix_web::test]
async fn sign_up_without_auto_sign_in_does_not_create_session() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(false, SocialProviders::new(vec![])));

    let req_body = json!({
        "name": "Test User",
        "email": "test@example.com",
        "password": "password123"
    });
    let response = sign_up_user!(app, req_body);

    assert_eq!(response.status(), StatusCode::CREATED);

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;

    assert_eq!(body["token"], Value::Null);

    let user_id = body["user"]["id"].as_str().unwrap();

    // ----- Check User from Database
    let user = database.find_user(UserFilter::Id(user_id)).await.unwrap();

    assert!(user.is_some());

    // ----- Check Account from Database
    let account = database
        .find_account(AccountFilter::UserId(user_id))
        .await
        .unwrap();

    assert!(account.is_some());

    // ----- Check Session from Database
    let session = database
        .find_session(SessionFilter::UserId(user_id))
        .await
        .unwrap();

    assert!(session.is_none());
}
