use std::sync::Arc;

use actix_web::{App, http::header, test, web};
use chrono::{Duration, Utc};
use reqwest::Url;
use serde_json::{Value, json};

use authr::{
    core::{
        auth::{AuthrContext, SocialProviders},
        oauth::{Provider, types::OAuthTransaction},
        types::Verification,
    },
    database::store::{AccountQuery, AuthDatabase, SessionQuery, UserQuery, VerificationQuery},
    http::router,
};

use crate::common::{
    MockOAuthProvider, TestDatabase, config, sign_in_social, sign_up_user, test_app,
};
// -------------------- Helpers --------------------

fn mock_providers(provider: MockOAuthProvider) -> SocialProviders {
    SocialProviders::new(vec![("mock".into(), Provider::Custom(Arc::new(provider)))])
}

async fn create_oauth_transaction(
    database: &TestDatabase,
    state: &str,
    provider_id: &str,
    callback_url: Option<String>,
) {
    let transaction = OAuthTransaction {
        provider_id: provider_id.into(),
        code_verifier: "mock-code-verifier".into(),
        callback_url,
    };

    let verification = Verification::new(
        format!("oauth:{state}"),
        serde_json::to_string(&transaction).unwrap(),
    );

    database.create_verification(verification).await.unwrap();
}

// -------------------- Social Sign-in --------------------

#[actix_web::test]
async fn sign_in_social_generates_authorization_url() {
    // ----- Setup
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, mock_providers(MockOAuthProvider::new()))
    );

    let req_body = json!({
        "provider": "mock"
    });

    let response = sign_in_social!(app, req_body);

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
    let verification = database
        .find_verification(VerificationQuery::Identifier(&format!(
            "oauth:{}",
            query["state"]
        )))
        .await
        .unwrap();

    assert!(verification.is_some());
}

#[actix_web::test]
async fn sign_in_social_uses_custom_scopes() {
    // ----- Setup
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, mock_providers(MockOAuthProvider::new()))
    );

    let req_body = json!({
        "provider": "mock",
        "scopes": ["email", "profile"]
    });

    let response = sign_in_social!(app, req_body);

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
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, mock_providers(MockOAuthProvider::new()))
    );

    let req_body = json!({
        "provider": "mock",
        "disableRedirect": true
    });

    let response = sign_in_social!(app, req_body);

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
    let database = TestDatabase::default();
    let app = test_app!(database);

    let req_body = json!({
        "provider": "unknown"
    });

    let response = sign_in_social!(app, req_body);

    // ----- Check Response
    assert!(!response.status().is_success());
}

// -------------------- Callback Validation --------------------

#[actix_web::test]
async fn callback_rejects_missing_state() {
    // ----- Setup
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, mock_providers(MockOAuthProvider::new()))
    );

    let request = test::TestRequest::get()
        .uri("/api/auth/callback/mock?code=mock-code")
        .to_request();

    let response = test::call_service(&app, request).await;

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
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, mock_providers(MockOAuthProvider::new()))
    );

    let request = test::TestRequest::get()
        .uri("/api/auth/callback/mock?code=mock-code&state=invalid-state")
        .to_request();

    let response = test::call_service(&app, request).await;

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
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, mock_providers(MockOAuthProvider::new()))
    );

    create_oauth_transaction(&database, "valid-state", "mock", None).await;

    let request = test::TestRequest::get()
        .uri("/api/auth/callback/mock?state=valid-state")
        .to_request();

    let response = test::call_service(&app, request).await;

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
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, mock_providers(MockOAuthProvider::new()))
    );

    create_oauth_transaction(&database, "valid-state", "another-provider", None).await;

    let request = test::TestRequest::get()
        .uri("/api/auth/callback/mock?code=mock-code&state=valid-state")
        .to_request();

    let response = test::call_service(&app, request).await;

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
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, mock_providers(MockOAuthProvider::new()))
    );

    let transaction = OAuthTransaction {
        provider_id: "mock".into(),
        code_verifier: "mock-verifier".into(),
        callback_url: Some("http://localhost:5173/callback".into()),
    };

    let mut verification = Verification::new(
        "oauth:expired-state".into(),
        serde_json::to_string(&transaction).unwrap(),
    );

    verification.expires_at = Utc::now() - Duration::minutes(1);

    database.create_verification(verification).await.unwrap();

    let request = test::TestRequest::get()
        .uri("/api/auth/callback/mock?code=mock-code&state=expired-state")
        .to_request();

    let response = test::call_service(&app, request).await;

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
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, mock_providers(MockOAuthProvider::new()))
    );

    create_oauth_transaction(
        &database,
        "valid-state",
        "mock",
        Some("http://localhost:5173/callback".into()),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/api/auth/callback/mock?code=mock-code&state=valid-state")
        .insert_header(("User-Agent", "Authr Tests"))
        .to_request();

    let response = test::call_service(&app, request).await;

    // ----- Check Response
    assert_eq!(response.status(), 302);

    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "http://localhost:5173/callback"
    );

    assert!(response.headers().contains_key(header::SET_COOKIE));

    // ----- Check User from Database
    let user = database
        .find_user(UserQuery::Email("mock@example.com"))
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
    let account = database
        .find_account(AccountQuery::Provider {
            provider_id: "mock",
            account_id: "mock-user-123",
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(account.user_id, user.id);
    assert_eq!(account.access_token.as_deref(), Some("mock-access-token"));
    assert_eq!(account.refresh_token.as_deref(), Some("mock-refresh-token"));
    assert_eq!(account.id_token.as_deref(), Some("mock-id-token"));

    // ----- Check Session from Database
    let sessions = database
        .find_sessions(SessionQuery::UserId(&user.id.to_string()))
        .await
        .unwrap();

    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].user_id, user.id);
}

// -------------------- Existing Accounts --------------------

#[actix_web::test]
async fn callback_links_oauth_account_to_existing_user() {
    // ----- Setup
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, mock_providers(MockOAuthProvider::new()))
    );

    let req_body = json!({
        "name": "Existing User",
        "email": "mock@example.com",
        "password": "password123"
    });

    let signup_response = sign_up_user!(app, req_body);
    assert!(signup_response.status().is_success());

    let existing_user = database
        .find_user(UserQuery::Email("mock@example.com"))
        .await
        .unwrap()
        .unwrap();

    create_oauth_transaction(
        &database,
        "valid-state",
        "mock",
        Some("http://localhost:5173/callback".into()),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/api/auth/callback/mock?code=mock-code&state=valid-state")
        .to_request();

    let response = test::call_service(&app, request).await;

    // ----- Check Response
    assert_eq!(response.status(), 302);

    // ----- Check Account Linking
    let account = database
        .find_account(AccountQuery::Provider {
            provider_id: "mock",
            account_id: "mock-user-123",
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(account.user_id, existing_user.id);

    // ----- Check User from Database
    let user = database
        .find_user(UserQuery::Email("mock@example.com"))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(user.id, existing_user.id);
}

// -------------------- Callback Failures --------------------

#[actix_web::test]
async fn callback_handles_token_exchange_failure() {
    // ----- Setup
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(
            true,
            mock_providers(MockOAuthProvider::failing_token_exchange())
        )
    );

    create_oauth_transaction(
        &database,
        "valid-state",
        "mock",
        Some("http://localhost:5173/callback".into()),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/api/auth/callback/mock?code=mock-code&state=valid-state")
        .to_request();

    let response = test::call_service(&app, request).await;

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
    let database = TestDatabase::default();
    let app = test_app!(
        database,
        config(true, mock_providers(MockOAuthProvider::failing_user_info()))
    );

    create_oauth_transaction(
        &database,
        "valid-state",
        "mock",
        Some("http://localhost:5173/callback".into()),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/api/auth/callback/mock?code=mock-code&state=valid-state")
        .to_request();

    let response = test::call_service(&app, request).await;

    // ----- Check Response
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(location.contains("error=user_info_failed"));
}
