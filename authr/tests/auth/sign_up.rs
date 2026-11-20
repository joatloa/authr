use actix_web::{App, http::StatusCode, test, web};
use chrono::Duration;
use serde_json::{Value, json};

use authr::{
    core::{
        auth::{AuthrConfig, AuthrData, BaseUrl, EmailAndPassword, SocialProviders},
        utils::create_argon,
    },
    database::store::{AccountQuery, AuthDatabase, SessionQuery, UserQuery},
    http::router,
};

use crate::common::TestDatabase;

// ----- Helpers

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();
}

fn config(auto_sign_in: bool) -> AuthrConfig {
    AuthrConfig {
        app_name: "Authr Tests".to_string(),
        base_url: BaseUrl::from("http://localhost:3000"),
        base_path: "/api/auth".to_string(),
        database_url: String::new(),
        secret: "test-secret-that-is-long-enough-for-testing".to_string(),
        email_and_password: EmailAndPassword {
            auto_sign_in,
            ..Default::default()
        },
        social_providers: SocialProviders::new(vec![]),
        disable_logs: true,
    }
}

macro_rules! test_app {
    ($database:expr, $config:expr) => {{
        let data = web::Data::new(AuthrData {
            database: $database.clone(),
            config: $config,
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

fn sign_up_body() -> Value {
    json!({
        "name": "John Doe",
        "email": "john@example.com",
        "password": "password123"
    })
}

// ----- Successful Registration

#[actix_web::test]
async fn sign_up_creates_user_account_and_session() {
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(true));

    let request = test::TestRequest::post()
        .uri("/api/auth/sign-up")
        .set_json(sign_up_body())
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::CREATED);

    // ----- Response
    let body: Value = test::read_body_json(response).await;

    assert!(!body["token"].as_str().unwrap_or_default().is_empty());
    assert_eq!(body["user"]["name"], "John Doe");
    assert_eq!(body["user"]["email"], "john@example.com");
    assert_eq!(body["user"]["image"], Value::Null);
    assert_eq!(body["user"]["emailVerified"], false);

    let user_id = body["user"]["id"].as_str().unwrap();

    // ----- User
    let user = database
        .find_user(UserQuery::Id(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(user.name, "John Doe");
    assert_eq!(user.email, "john@example.com");

    // ----- Account
    let account = database
        .find_account(AccountQuery::UserId(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(account.provider_id, "credential");
    assert!(account.password_hash.is_some());

    // ----- Session
    let session = database
        .find_session(SessionQuery::UserId(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(session.user_id, user.id);
}

// ----- Email Normalization

#[actix_web::test]
async fn sign_up_normalizes_email_to_lowercase() {
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(true));

    let request = test::TestRequest::post()
        .uri("/api/auth/sign-up")
        .set_json(json!({
            "name": "John Doe",
            "email": "JOHN@EXAMPLE.COM",
            "password": "password123"
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let user = database
        .find_user(UserQuery::Email("john@example.com"))
        .await
        .unwrap();

    assert!(user.is_some());
}

// ----- Duplicate Email

#[actix_web::test]
async fn sign_up_returns_generic_response_for_existing_email() {
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(false));

    let request = || {
        test::TestRequest::post()
            .uri("/api/auth/sign-up")
            .set_json(sign_up_body())
            .to_request()
    };

    // ----- First sign-up
    let first_response = test::call_service(&app, request()).await;
    assert_eq!(first_response.status(), StatusCode::CREATED);

    let first_body: Value = test::read_body_json(first_response).await;
    let first_user_id = first_body["user"]["id"].as_str().unwrap();

    // ----- Duplicate sign-up
    let second_response = test::call_service(&app, request()).await;
    assert_eq!(second_response.status(), StatusCode::CREATED);

    let second_body: Value = test::read_body_json(second_response).await;

    assert!(second_body["token"].is_null());

    let second_user_id = second_body["user"]["id"].as_str().unwrap();
    assert_ne!(first_user_id, second_user_id);

    // ----- Verify database
    let existing_user = database
        .find_user(UserQuery::Id(first_user_id))
        .await
        .unwrap();

    let synthetic_user = database
        .find_user(UserQuery::Id(second_user_id))
        .await
        .unwrap();

    assert!(existing_user.is_some());
    assert!(synthetic_user.is_none());
}

// ----- Validation

#[actix_web::test]
async fn sign_up_rejects_invalid_email() {
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(true));

    let request = test::TestRequest::post()
        .uri("/api/auth/sign-up")
        .set_json(json!({
            "name": "John Doe",
            "email": "invalid-email",
            "password": "password123"
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn sign_up_rejects_short_password() {
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(true));

    let request = test::TestRequest::post()
        .uri("/api/auth/sign-up")
        .set_json(json!({
            "name": "John Doe",
            "email": "john@example.com",
            "password": "short"
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn sign_up_rejects_long_password() {
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(true));

    let request = test::TestRequest::post()
        .uri("/api/auth/sign-up")
        .set_json(json!({
            "name": "John Doe",
            "email": "john@example.com",
            "password": "a".repeat(129)
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn sign_up_rejects_empty_name() {
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(true));

    let request = test::TestRequest::post()
        .uri("/api/auth/sign-up")
        .set_json(json!({
            "name": "   ",
            "email": "john@example.com",
            "password": "password123"
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn sign_up_rejects_missing_fields() {
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(true));

    let request = test::TestRequest::post()
        .uri("/api/auth/sign-up")
        .set_json(json!({
            "email": "john@example.com",
            "password": "password123"
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ----- Remember Me

#[actix_web::test]
async fn sign_up_creates_long_lived_session_when_remember_me_is_true() {
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(true));

    let request = test::TestRequest::post()
        .uri("/api/auth/sign-up")
        .set_json(json!({
            "name": "John Doe",
            "email": "john@example.com",
            "password": "password123",
            "rememberMe": true
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let body: Value = test::read_body_json(response).await;
    let user_id = body["user"]["id"].as_str().unwrap();

    let session = database
        .find_session(SessionQuery::UserId(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(session.expires_at - session.created_at, Duration::days(30));
}

#[actix_web::test]
async fn sign_up_creates_short_lived_session_when_remember_me_is_false() {
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(true));

    let request = test::TestRequest::post()
        .uri("/api/auth/sign-up")
        .set_json(json!({
            "name": "John Doe",
            "email": "john@example.com",
            "password": "password123",
            "rememberMe": false
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let body: Value = test::read_body_json(response).await;
    let user_id = body["user"]["id"].as_str().unwrap();

    let session = database
        .find_session(SessionQuery::UserId(user_id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(session.expires_at - session.created_at, Duration::days(1));
}

// ----- Automatic Sign-In

#[actix_web::test]
async fn sign_up_without_auto_sign_in_does_not_create_session() {
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database, config(false));

    let request = test::TestRequest::post()
        .uri("/api/auth/sign-up")
        .set_json(sign_up_body())
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let body: Value = test::read_body_json(response).await;

    assert_eq!(body["token"], Value::Null);

    let user_id = body["user"]["id"].as_str().unwrap();

    // ----- User
    let user = database.find_user(UserQuery::Id(user_id)).await.unwrap();

    assert!(user.is_some());

    // ----- Account
    let account = database
        .find_account(AccountQuery::UserId(user_id))
        .await
        .unwrap();

    assert!(account.is_some());

    // ----- Session
    let session = database
        .find_session(SessionQuery::UserId(user_id))
        .await
        .unwrap();

    assert!(session.is_none());
}
