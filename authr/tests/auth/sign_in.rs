use actix_web::http::{StatusCode, header};
use actix_web::test;
use chrono::Duration;
use serde_json::{Value, json};

use crate::common::{
    helpers::{call, test_app},
    log::init_tracing,
    mock::TestDatabase,
};

// ----- Tests
#[actix_web::test]
async fn sign_in_creates_session_and_sets_cookie() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);
    let store = database.to_authr_store();

    let sign_up_response = call!(
        app,
        POST,
        "/api/auth/sign-up",
        json = json!({
            "name": "Test User",
            "email": "test@example.com",
            "password": "password123"
        })
    );
    assert_eq!(sign_up_response.status(), StatusCode::CREATED);

    // ----- Send sign-in request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-in/email",
        json = json!({
            "email": "test@example.com",
            "password": "password123"
        })
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(set_cookie.contains("authr_session="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("Secure"));
    assert!(set_cookie.contains("SameSite=Lax"));

    // ----- Verify response body
    let body: Value = test::read_body_json(response).await;

    assert!(body["token"].is_string());
    assert_eq!(body["user"]["email"], "test@example.com");
    assert_eq!(body["user"]["name"], "Test User");
    assert!(body["user"]["id"].is_string());

    // ----- Verify session creation
    let token = body["token"].as_str().unwrap();

    let session = store.find_session_by_token(token).await.unwrap();

    assert!(session.is_some());
}

#[actix_web::test]
async fn sign_in_stores_user_agent() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);
    let store = database.to_authr_store();

    let sign_up_response = call!(
        app,
        POST,
        "/api/auth/sign-up",
        json = json!({
            "name": "Test User",
            "email": "test@example.com",
            "password": "password123"
        })
    );
    assert_eq!(sign_up_response.status(), StatusCode::CREATED);

    // ----- Send sign-in request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-in/email",
        json = json!({
            "email": "test@example.com",
            "password": "password123"
        }),
        headers = [(header::USER_AGENT, "Authr Test")]
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;
    let token = body["token"].as_str().unwrap();

    // ----- Verify session metadata
    let session = store.find_session_by_token(token).await.unwrap().unwrap();

    assert_eq!(session.user_agent.as_deref(), Some("Authr Test"));
}

#[actix_web::test]
async fn sign_in_respects_remember_me() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);
    let store = database.to_authr_store();

    let sign_up_response = call!(
        app,
        POST,
        "/api/auth/sign-up",
        json = json!({
            "name": "Test User",
            "email": "test@example.com",
            "password": "password123"
        })
    );
    assert_eq!(sign_up_response.status(), StatusCode::CREATED);

    // ----- Send sign-in request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-in/email",
        json = json!({
            "email": "test@example.com",
            "password": "password123",
            "rememberMe": false
        })
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;
    let token = body["token"].as_str().unwrap();

    // ----- Verify session expiration
    let session = store.find_session_by_token(token).await.unwrap().unwrap();

    assert_eq!(session.expires_at - session.created_at, Duration::days(1));
}

#[actix_web::test]
async fn sign_in_with_invalid_password_fails() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let sign_up_response = call!(
        app,
        POST,
        "/api/auth/sign-up",
        json = json!({
            "name": "Test User",
            "email": "test@example.com",
            "password": "password123"
        })
    );
    assert_eq!(sign_up_response.status(), StatusCode::CREATED);

    // ----- Send sign-in request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-in/email",
        json = json!({
            "email": "test@example.com",
            "password": "wrong-password"
        })
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn sign_in_with_nonexistent_email_fails() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    // ----- Send sign-in request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-in/email",
        json = json!({
            "email": "missing@example.com",
            "password": "password123"
        })
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn sign_in_with_invalid_email_fails() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    // ----- Send sign-in request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-in/email",
        json = json!({
            "email": "invalid-email",
            "password": "password123"
        })
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn sign_in_with_short_password_fails() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    // ----- Send sign-in request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-in/email",
        json = json!({
            "email": "test@example.com",
            "password": "short"
        })
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
