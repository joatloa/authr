use actix_web::{http::header, test};
use chrono::{Duration, Utc};
use reqwest::Url;
use serde_json::{Value, json};

use authr::core::{oauth::types::OAuthTransaction, types::Verification};

use crate::common::{
    helpers::{call, config, seed_oauth_transaction, test_app},
    log::init_tracing,
    mock::{MockOAuthProvider, TestDatabase},
};

// -------------------- Social Sign-in --------------------

#[actix_web::test]
async fn sign_in_social_generates_authorization_url() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, MockOAuthProvider::new().into_social_providers())
    );
    let store = database.to_authr_store();

    let req_body = json!({
        "provider": "mock"
    });

    let response = call!(app, POST, "/api/auth/sign-in/social", json = req_body);

    // ----- Check Response
    assert_eq!(response.status(), 200);

    let location = response.headers().get(header::LOCATION).unwrap().clone();
    let body: Value = test::read_body_json(response).await;

    assert_eq!(body["redirect"], true);

    let authorization_url = Url::parse(body["url"].as_str().unwrap()).unwrap();

    assert_eq!(authorization_url.host_str(), Some("mock.example"));

    let query: std::collections::HashMap<String, String> =
        authorization_url.query_pairs().into_owned().collect();

    assert_eq!(query["response_type"], "code");
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["scope"], "openid email profile");
    assert!(!query["state"].is_empty());
    assert!(!query["code_challenge"].is_empty());

    assert_eq!(location.to_str().unwrap(), authorization_url.as_str());

    // ----- Check OAuth Transaction
    let verification = store
        .find_verification_by_identifier(&format!("oauth:{}", query["state"]))
        .await
        .unwrap();

    assert!(verification.is_some());
}

#[actix_web::test]
async fn sign_in_social_uses_custom_scopes() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, MockOAuthProvider::new().into_social_providers())
    );

    let req_body = json!({
        "provider": "mock",
        "scopes": ["email", "profile"]
    });

    let response = call!(app, POST, "/api/auth/sign-in/social", json = req_body);

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;
    let authorization_url = Url::parse(body["url"].as_str().unwrap()).unwrap();

    let scopes = authorization_url
        .query_pairs()
        .find(|(key, _)| key == "scope")
        .unwrap()
        .1;

    assert_eq!(scopes, "email profile");
}

#[actix_web::test]
async fn sign_in_social_can_disable_redirect() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, MockOAuthProvider::new().into_social_providers())
    );

    let req_body = json!({
        "provider": "mock",
        "disableRedirect": true
    });

    let response = call!(app, POST, "/api/auth/sign-in/social", json = req_body);

    // ----- Check Response
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key(header::LOCATION));

    let body: Value = test::read_body_json(response).await;

    assert_eq!(body["redirect"], false);
    assert!(body["url"].as_str().is_some());
}

#[actix_web::test]
async fn sign_in_social_rejects_unknown_provider() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(database);

    let req_body = json!({
        "provider": "unknown"
    });

    let response = call!(app, POST, "/api/auth/sign-in/social", json = req_body);

    // ----- Check Response
    assert!(!response.status().is_success());
}

// -------------------- Callback Validation --------------------

#[actix_web::test]
async fn callback_rejects_missing_state() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, MockOAuthProvider::new().into_social_providers())
    );

    let response = call!(app, GET, "/api/auth/callback/mock?code=mock-code");

    // ----- Check Response
    assert_eq!(response.status(), 302);

    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(location.contains("error=state_not_found"));
}

#[actix_web::test]
async fn callback_rejects_invalid_state() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, MockOAuthProvider::new().into_social_providers())
    );

    let response = call!(
        app,
        GET,
        "/api/auth/callback/mock?code=mock-code&state=invalid-state"
    );

    // ----- Check Response
    assert_eq!(response.status(), 302);

    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(location.contains("error=invalid_state"));
}

#[actix_web::test]
async fn callback_rejects_missing_code() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, MockOAuthProvider::new().into_social_providers())
    );

    seed_oauth_transaction(&database, "valid-state", "mock", None).await;

    let response = call!(app, GET, "/api/auth/callback/mock?state=valid-state");

    // ----- Check Response
    assert_eq!(response.status(), 302);

    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(location.contains("error=code_not_found"));
}

#[actix_web::test]
async fn callback_rejects_provider_mismatch() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, MockOAuthProvider::new().into_social_providers())
    );

    seed_oauth_transaction(&database, "valid-state", "another-provider", None).await;

    let response = call!(
        app,
        GET,
        "/api/auth/callback/mock?code=mock-code&state=valid-state"
    );

    // ----- Check Response
    assert_eq!(response.status(), 302);

    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(location.contains("error=provider_mismatch"));
}

#[actix_web::test]
async fn callback_rejects_expired_state() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, MockOAuthProvider::new().into_social_providers())
    );

    let transaction = OAuthTransaction {
        provider_id: "mock".into(),
        code_verifier: "mock-verifier".into(),
        callback_url: Some("http://localhost:5173/callback".into()),
    };

    let mut verification = Verification::new(
        "oauth:expired-state".into(),
        serde_json::to_string(&transaction).unwrap(),
        Utc::now() + Duration::days(10),
    );

    verification.expires_at = Utc::now() - Duration::minutes(1);

    database
        .to_authr_store()
        .create_verification(verification)
        .await
        .unwrap();

    let response = call!(
        app,
        GET,
        "/api/auth/callback/mock?code=mock-code&state=expired-state"
    );

    // ----- Check Response
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(location.contains("error=state_expired"));
}

// -------------------- Successful Callback --------------------

#[actix_web::test]
async fn callback_creates_user_account_and_session() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, MockOAuthProvider::new().into_social_providers())
    );
    let store = database.to_authr_store();

    seed_oauth_transaction(
        &database,
        "valid-state",
        "mock",
        Some("http://localhost:5173/callback".into()),
    )
    .await;

    let response = call!(
        app,
        GET,
        "/api/auth/callback/mock?code=mock-code&state=valid-state",
        headers = [(header::USER_AGENT, "Authr Tests")]
    );

    // ----- Check Response
    assert_eq!(response.status(), 302);

    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "http://localhost:5173/callback"
    );

    assert!(response.headers().contains_key(header::SET_COOKIE));

    // ----- Check User from Database
    let user = store
        .find_user_by_email("mock@example.com")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(user.name, "Mock User");
    assert!(user.email_verified);
    assert_eq!(
        user.image.as_deref(),
        Some("https://mock.example/avatar.png")
    );

    // ----- Check Account from Database
    let account = store
        .find_account_by_provider("mock", "mock-user-123")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(account.user_id, user.id);
    assert_eq!(account.access_token.as_deref(), Some("mock-access-token"));
    assert_eq!(account.refresh_token.as_deref(), Some("mock-refresh-token"));
    assert_eq!(account.id_token.as_deref(), Some("mock-id-token"));

    // ----- Check Session from Database
    let sessions = store
        .find_sessions_by_user_id(&user.id.to_string())
        .await
        .unwrap();

    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].user_id, user.id);
}

// -------------------- Existing Accounts --------------------

#[actix_web::test]
async fn callback_links_oauth_account_to_existing_user() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, MockOAuthProvider::new().into_social_providers())
    );
    let store = database.to_authr_store();

    let req_body = json!({
        "name": "Existing User",
        "email": "mock@example.com",
        "password": "password123"
    });

    let signup_response = call!(app, POST, "/api/auth/sign-up", json = req_body);
    assert!(signup_response.status().is_success());

    let existing_user = store
        .find_user_by_email("mock@example.com")
        .await
        .unwrap()
        .unwrap();

    seed_oauth_transaction(
        &database,
        "valid-state",
        "mock",
        Some("http://localhost:5173/callback".into()),
    )
    .await;

    let response = call!(
        app,
        GET,
        "/api/auth/callback/mock?code=mock-code&state=valid-state"
    );

    // ----- Check Response
    assert_eq!(response.status(), 302);

    // ----- Check Account Linking
    let account = store
        .find_account_by_provider("mock", "mock-user-123")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(account.user_id, existing_user.id);

    // ----- Check User from Database
    let user = store
        .find_user_by_email("mock@example.com")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(user.id, existing_user.id);
}

// -------------------- Callback Failures --------------------

#[actix_web::test]
async fn callback_handles_token_exchange_failure() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(
            true,
            MockOAuthProvider::failing_token_exchange().into_social_providers()
        )
    );

    seed_oauth_transaction(
        &database,
        "valid-state",
        "mock",
        Some("http://localhost:5173/callback".into()),
    )
    .await;

    let response = call!(
        app,
        GET,
        "/api/auth/callback/mock?code=mock-code&state=valid-state"
    );

    // ----- Check Response
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(location.contains("error=token_exchange_failed"));
}

#[actix_web::test]
async fn callback_handles_user_info_failure() {
    // ----- Setup
    init_tracing();
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(
            true,
            MockOAuthProvider::failing_user_info().into_social_providers()
        )
    );

    seed_oauth_transaction(
        &database,
        "valid-state",
        "mock",
        Some("http://localhost:5173/callback".into()),
    )
    .await;

    let response = call!(
        app,
        GET,
        "/api/auth/callback/mock?code=mock-code&state=valid-state"
    );

    // ----- Check Response
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(location.contains("error=user_info_failed"));
}
