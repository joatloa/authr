use actix_web::{
    App,
    http::{StatusCode, header},
    test, web,
};
use chrono::Duration;
use serde_json::{Value, json};

use authr::{
    core::{
        auth::{AuthrConfig, AuthrData, BaseUrl, EmailAndPassword, SocialProviders},
        utils::create_argon,
    },
    database::store::{AuthDatabase, SessionQuery},
    http::router,
};

use crate::common::TestDatabase;

// ----- Test setup

fn config() -> AuthrConfig {
    AuthrConfig {
        app_name: "Authr Tests".to_string(),
        base_url: BaseUrl::Link {
            host: "http://localhost:3000".to_string(),
        },
        database_url: String::new(),
        base_path: "/api/auth".to_string(),
        email_and_password: EmailAndPassword::default(),
        social_providers: SocialProviders::new(vec![]),
        secret: "test-secret-that-is-long-enough-for-testing".to_string(),
        disable_logs: true,
    }
}

macro_rules! test_app {
    ($database:expr) => {{
        let data = web::Data::new(AuthrData {
            database: $database.clone(),
            config: config(),
            argon: create_argon(),
        });

        test::init_service(
            App::new()
                .app_data(data)
                .service(web::scope("/api/auth").configure(router::config::<TestDatabase>)),
        )
        .await
    }};
}

macro_rules! sign_up_user {
    ($app:expr) => {{
        let request = test::TestRequest::post()
            .uri("/api/auth/sign-up/email")
            .set_json(json!({
                "name": "Test User",
                "email": "test@example.com",
                "password": "password123"
            }))
            .to_request();

        test::call_service(&$app, request).await
    }};
}

// ----- Tests

#[actix_web::test]
async fn sign_in_creates_session_and_sets_cookie() {
    // ----- Setup
    let database = TestDatabase::default();
    let app = test_app!(database);

    let sign_up_response = sign_up_user!(app);
    assert_eq!(sign_up_response.status(), StatusCode::CREATED);

    // ----- Send sign-in request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-in/email")
        .set_json(json!({
            "email": "test@example.com",
            "password": "password123"
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

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

    let session = database
        .find_session(SessionQuery::Token(token))
        .await
        .unwrap();

    assert!(session.is_some());
}

#[actix_web::test]
async fn sign_in_stores_user_agent() {
    // ----- Setup
    let database = TestDatabase::default();
    let app = test_app!(database);

    let sign_up_response = sign_up_user!(app);
    assert_eq!(sign_up_response.status(), StatusCode::CREATED);

    // ----- Send sign-in request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-in/email")
        .insert_header((header::USER_AGENT, "Authr Test"))
        .set_json(json!({
            "email": "test@example.com",
            "password": "password123"
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;
    let token = body["token"].as_str().unwrap();

    // ----- Verify session metadata
    let session = database
        .find_session(SessionQuery::Token(token))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(session.user_agent.as_deref(), Some("Authr Test"));
}

#[actix_web::test]
async fn sign_in_respects_remember_me() {
    // ----- Setup
    let database = TestDatabase::default();
    let app = test_app!(database);

    let sign_up_response = sign_up_user!(app);
    assert_eq!(sign_up_response.status(), StatusCode::CREATED);

    // ----- Send sign-in request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-in/email")
        .set_json(json!({
            "email": "test@example.com",
            "password": "password123",
            "rememberMe": false
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;
    let token = body["token"].as_str().unwrap();

    // ----- Verify session expiration
    let session = database
        .find_session(SessionQuery::Token(token))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(session.expires_at - session.created_at, Duration::days(1));
}

#[actix_web::test]
async fn sign_in_with_invalid_password_fails() {
    // ----- Setup
    let database = TestDatabase::default();
    let app = test_app!(database);

    let sign_up_response = sign_up_user!(app);
    assert_eq!(sign_up_response.status(), StatusCode::CREATED);

    // ----- Send sign-in request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-in/email")
        .set_json(json!({
            "email": "test@example.com",
            "password": "wrong-password"
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn sign_in_with_nonexistent_email_fails() {
    // ----- Setup
    let database = TestDatabase::default();
    let app = test_app!(database);

    // ----- Send sign-in request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-in/email")
        .set_json(json!({
            "email": "missing@example.com",
            "password": "password123"
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn sign_in_with_invalid_email_fails() {
    // ----- Setup
    let database = TestDatabase::default();
    let app = test_app!(database);

    // ----- Send sign-in request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-in/email")
        .set_json(json!({
            "email": "invalid-email",
            "password": "password123"
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn sign_in_with_short_password_fails() {
    // ----- Setup
    let database = TestDatabase::default();
    let app = test_app!(database);

    // ----- Send sign-in request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-in/email")
        .set_json(json!({
            "email": "test@example.com",
            "password": "short"
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
