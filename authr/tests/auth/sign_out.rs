use actix_web::{
    App,
    http::{StatusCode, header},
    test, web,
};
use serde_json::{Value, json};

use authr::{
    core::{
        auth::{AuthrConfig, AuthrContext, BaseUrl, EmailAndPassword, SocialProviders},
        oauth::{Provider, providers::GoogleProvider},
        types::{Account, Session, User},
    },
    database::store::{AuthDatabase, SessionQuery},
    http::router,
};

use crate::common::{TestDatabase, config, init_tracing, test_app};

// ----- Helpers
async fn create_session(database: &TestDatabase) -> Session {
    let user = database
        .create_user(User::new(
            "Test User".to_string(),
            "test@example.com".to_string(),
            false,
            None,
        ))
        .await
        .unwrap();

    database
        .create_session(Session::new(user.id, None, None), false)
        .await
        .unwrap()
}
#[actix_web::test]
async fn sign_out_deletes_session_and_clears_cookie() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let session = create_session(&database).await;
    let token = session.token.clone();

    let app = test_app!(database);

    // ----- Send sign-out request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-out")
        .insert_header((header::COOKIE, format!("authr_session={token}")))
        .set_json(json!({}))
        .to_request();

    let response = test::call_service(&app, request).await;

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
    let deleted_session = database
        .find_session(SessionQuery::Token(&token))
        .await
        .unwrap();

    assert!(deleted_session.is_none());
}

#[actix_web::test]
async fn sign_out_succeeds_without_session_cookie() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    // ----- Send sign-out request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-out")
        .set_json(json!({}))
        .to_request();

    let response = test::call_service(&app, request).await;

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
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-out")
        .insert_header((header::COOKIE, "authr_session=invalid-token"))
        .set_json(json!({}))
        .to_request();

    let response = test::call_service(&app, request).await;

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, json!({ "success": true }));
}

// -------------------- Social Provider -------------------------
async fn create_google_account(database: &TestDatabase, user_id: uuid::Uuid) -> Account {
    let mut account = Account::new_social(
        user_id,
        "google".to_string(),
        "google-user-id".to_string(),
        Some("access-token".to_string()),
        Some("refresh-token".to_string()),
        None,
        None,
        Some("openid email profile".to_string()),
        Some("test-id-token".to_string()),
    );

    account.updated_at = chrono::Utc::now();

    database.create_account(account.clone()).await.unwrap();

    account
}

fn config_with_providers(providers: Vec<(String, Provider)>) -> AuthrConfig {
    AuthrConfig {
        app_name: "Authr Tests".to_string(),
        base_url: BaseUrl::from("http://localhost:3000"),
        base_path: "/api/auth".to_string(),
        database_url: String::new(),
        secret: "test-secret-that-is-long-enough-for-testing".to_string(),
        email_and_password: EmailAndPassword::default(),
        social_providers: SocialProviders::new(providers),
        disable_logs: true,
    }
}

#[actix_web::test]
async fn sign_out_redirects_to_provider_logout() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let session = create_session(&database).await;
    let token = session.token.clone();

    create_google_account(&database, session.user_id).await;

    let providers = vec![(
        "google".to_string(),
        Provider::Google(GoogleProvider::new("test-client-id", "test-client-secret")),
    )];

    let app = test_app!(database, config_with_providers(providers));

    // ----- Send sign-out request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-out")
        .insert_header((header::COOKIE, format!("authr_session={token}")))
        .set_json(json!({}))
        .to_request();

    let response = test::call_service(&app, request).await;

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
    assert!(
        database
            .find_session(SessionQuery::Token(&token))
            .await
            .unwrap()
            .is_none()
    );
}

#[actix_web::test]
async fn sign_out_respects_disable_redirect() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let session = create_session(&database).await;

    create_google_account(&database, session.user_id).await;

    let providers = vec![(
        "google".to_string(),
        Provider::Google(GoogleProvider::new("test-client-id", "test-client-secret")),
    )];

    let app = test_app!(database, config_with_providers(providers));

    // ----- Send sign-out request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-out")
        .insert_header((header::COOKIE, format!("authr_session={}", session.token)))
        .set_json(json!({
            "disableRedirect": true
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

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
    let session = create_session(&database).await;

    create_google_account(&database, session.user_id).await;

    let providers = vec![(
        "google".to_string(),
        Provider::Google(GoogleProvider::new("test-client-id", "test-client-secret")),
    )];

    let app = test_app!(database, config_with_providers(providers));

    // ----- Send sign-out request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-out")
        .insert_header((header::COOKIE, format!("authr_session={}", session.token)))
        .set_json(json!({
            "callbackUrl": "/goodbye",
            "state": "logout-state",
            "disableRedirect": true
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

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
    let session = create_session(&database).await;
    let token = session.token.clone();

    let providers = vec![(
        "google".to_string(),
        Provider::Google(GoogleProvider::new("test-client-id", "test-client-secret")),
    )];

    let app = test_app!(database, config_with_providers(providers));

    // ----- Send sign-out request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-out")
        .insert_header((header::COOKIE, format!("authr_session={token}")))
        .set_json(json!({}))
        .to_request();

    let response = test::call_service(&app, request).await;

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, json!({ "success": true }));

    // ----- Verify local session was revoked
    assert!(
        database
            .find_session(SessionQuery::Token(&token))
            .await
            .unwrap()
            .is_none()
    );
}

#[actix_web::test]
async fn sign_out_attempts_provider_logout_without_id_token() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let session = create_session(&database).await;

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

    database.create_account(account).await.unwrap();

    let providers = vec![(
        "google".to_string(),
        Provider::Google(GoogleProvider::new("test-client-id", "test-client-secret")),
    )];

    let app = test_app!(database, config_with_providers(providers));

    // ----- Send sign-out request
    let request = test::TestRequest::post()
        .uri("/api/auth/sign-out")
        .insert_header((header::COOKIE, format!("authr_session={}", session.token)))
        .set_json(json!({
            "disableRedirect": true
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    // ----- Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;

    assert_eq!(body["success"], true);
    assert_eq!(body["redirect"], false);

    // ----- Verify provider logout URL omits ID token hint
    let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();

    assert!(!url.query_pairs().any(|(key, _)| key == "id_token_hint"));
}
