use actix_web::{
    http::{StatusCode, header},
    test,
};
use serde_json::{Value, json};

use authr::core::{
    auth::SocialProviders,
    oauth::{Provider, providers::GoogleProvider},
    types::Account,
};

use crate::common::{
    helpers::{call, config, seed_account, seed_session, seed_user, test_app},
    log::init_tracing,
    mock::TestDatabase,
};

#[actix_web::test]
async fn sign_out_deletes_session_and_clears_cookie() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;
    let session = seed_session(&database, user.id).await;
    let token = session.token.clone();

    let app = test_app!(database);
    let store = database.to_authr_store();

    // ----- Send sign-out request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-out",
        json = json!({}),
        headers = [(header::COOKIE, format!("authr_session={token}"))]
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, json!({ "success": true }));

    // ----- Verify cookie removal
    assert!(set_cookie.contains("authr_session="));
    assert!(set_cookie.contains("Max-Age=0"));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("Secure"));
    assert!(set_cookie.contains("SameSite=Lax"));

    // ----- Verify session deletion
    let deleted_session = store.find_session_by_token(&token).await.unwrap();

    assert!(deleted_session.is_none());
}

#[actix_web::test]
async fn sign_out_succeeds_without_session_cookie() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    // ----- Send sign-out request
    let response = call!(app, POST, "/api/auth/sign-out", json = json!({}));

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, json!({ "success": true }));

    // ----- Verify cookie removal
    assert!(set_cookie.contains("authr_session="));
    assert!(set_cookie.contains("Max-Age=0"));
}

#[actix_web::test]
async fn sign_out_succeeds_with_invalid_session_token() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    // ----- Send sign-out request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-out",
        json = json!({}),
        headers = [(header::COOKIE, "authr_session=invalid-token")]
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, json!({ "success": true }));
}

// -------------------- Social Provider -------------------------
#[actix_web::test]
async fn sign_out_redirects_to_provider_logout() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;
    let session = seed_session(&database, user.id).await;
    let token = session.token.clone();

    seed_account(
        &database,
        Account::new_social(
            session.user_id,
            "google".into(),
            "google-user-id".into(),
            Some("access-token".into()),
            Some("refresh-token".into()),
            None,
            None,
            Some("openid email profile".into()),
            Some("test-id-token".into()),
        ),
    )
    .await;

    let providers = SocialProviders::new(vec![(
        "google".to_string(),
        Provider::Google(GoogleProvider::new("test-client-id", "test-client-secret")),
    )]);

    let app = test_app!(database, config(true, providers));
    let store = database.to_authr_store();

    // ----- Send sign-out request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-out",
        json = json!({}),
        headers = [(header::COOKIE, format!("authr_session={token}"))]
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    assert!(location.starts_with("https://accounts.google.com/Logout"));

    let body: Value = test::read_body_json(response).await;

    assert_eq!(body["success"], true);
    assert_eq!(body["redirect"], true);
    assert_eq!(body["url"], location);

    // ----- Verify provider logout parameters
    let query: std::collections::HashMap<_, _> = url::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();

    assert_eq!(
        query.get("id_token_hint").map(String::as_str),
        Some("test-id-token")
    );

    // ----- Verify local session was revoked
    assert!(store.find_session_by_token(&token).await.unwrap().is_none());
}

#[actix_web::test]
async fn sign_out_respects_disable_redirect() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;
    let session = seed_session(&database, user.id).await;

    seed_account(
        &database,
        Account::new_social(
            session.user_id,
            "google".into(),
            "google-user-id".into(),
            Some("access-token".into()),
            Some("refresh-token".into()),
            None,
            None,
            Some("openid email profile".into()),
            Some("test-id-token".into()),
        ),
    )
    .await;

    let providers = SocialProviders::new(vec![(
        "google".to_string(),
        Provider::Google(GoogleProvider::new("test-client-id", "test-client-secret")),
    )]);

    let app = test_app!(database, config(true, providers));

    // ----- Send sign-out request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-out",
        json = json!({
            "disableRedirect": true
        }),
        headers = [(header::COOKIE, format!("authr_session={}", session.token))]
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::LOCATION).is_none());

    let body: Value = test::read_body_json(response).await;

    assert_eq!(body["success"], true);
    assert_eq!(body["redirect"], false);
    assert!(
        body["url"]
            .as_str()
            .unwrap()
            .starts_with("https://accounts.google.com/Logout")
    );
}

#[actix_web::test]
async fn sign_out_includes_callback_url_and_state() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;
    let session = seed_session(&database, user.id).await;

    seed_account(
        &database,
        Account::new_social(
            session.user_id,
            "google".into(),
            "google-user-id".into(),
            Some("access-token".into()),
            Some("refresh-token".into()),
            None,
            None,
            Some("openid email profile".into()),
            Some("test-id-token".into()),
        ),
    )
    .await;

    let providers = SocialProviders::new(vec![(
        "google".to_string(),
        Provider::Google(GoogleProvider::new("test-client-id", "test-client-secret")),
    )]);

    let app = test_app!(database, config(true, providers));

    // ----- Send sign-out request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-out",
        json = json!({
            "callbackUrl": "/goodbye",
            "state": "logout-state",
            "disableRedirect": true
        }),
        headers = [(header::COOKIE, format!("authr_session={}", session.token))]
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;
    let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();

    // ----- Verify provider logout parameters
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();

    assert_eq!(
        query.get("post_logout_redirect_uri").map(String::as_str),
        Some("http://localhost:3000/goodbye")
    );
    assert_eq!(query.get("state").map(String::as_str), Some("logout-state"));
}

#[actix_web::test]
async fn sign_out_without_social_account_only_revokes_session() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;
    let session = seed_session(&database, user.id).await;
    let token = session.token.clone();

    let providers = SocialProviders::new(vec![(
        "google".to_string(),
        Provider::Google(GoogleProvider::new("test-client-id", "test-client-secret")),
    )]);

    let app = test_app!(database, config(true, providers));
    let store = database.to_authr_store();

    // ----- Send sign-out request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-out",
        json = json!({}),
        headers = [(header::COOKIE, format!("authr_session={token}"))]
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, json!({ "success": true }));

    // ----- Verify local session was revoked
    assert!(store.find_session_by_token(&token).await.unwrap().is_none());
}

#[actix_web::test]
async fn sign_out_attempts_provider_logout_without_id_token() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;
    let session = seed_session(&database, user.id).await;

    let store = database.to_authr_store();

    let account = Account::new_social(
        session.user_id,
        "google".to_string(),
        "google-user-id".to_string(),
        Some("access-token".to_string()),
        None,
        None,
        None,
        Some("openid email profile".to_string()),
        None,
    );

    store.create_account(account).await.unwrap();

    let providers = SocialProviders::new(vec![(
        "google".to_string(),
        Provider::Google(GoogleProvider::new("test-client-id", "test-client-secret")),
    )]);

    let app = test_app!(database, config(true, providers));

    // ----- Send sign-out request
    let response = call!(
        app,
        POST,
        "/api/auth/sign-out",
        json = json!({
            "disableRedirect": true
        }),
        headers = [(header::COOKIE, format!("authr_session={}", session.token))]
    );

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;

    assert_eq!(body["success"], true);
    assert_eq!(body["redirect"], false);

    // ----- Verify provider logout URL omits ID token hint
    let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();

    assert!(!url.query_pairs().any(|(key, _)| key == "id_token_hint"));
}
