use std::sync::{Arc, Mutex};

use actix_web::{
    App,
    http::{StatusCode, header},
    test, web,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::{Value, json};

use authr::core::{
    auth::{AuthrContext, EmailAndPassword, PasswordResetSender},
    error::AuthrError,
};
use authr::http::router;

use crate::common::{TestDatabase, config, init_tracing, sign_up_user, test_app};

// -------------------- Mock Password Reset Sender --------------------

#[derive(Debug, Clone, Default)]
struct RecordingResetSender(Arc<Mutex<Vec<(String, String)>>>);

impl RecordingResetSender {
    fn last_token(&self) -> String {
        self.0.lock().unwrap().last().unwrap().1.clone()
    }

    fn last_url(&self) -> String {
        self.0.lock().unwrap().last().unwrap().0.clone()
    }
}

#[async_trait]
impl PasswordResetSender for RecordingResetSender {
    async fn send_reset_password(
        &self,
        _user: authr::core::types::User,
        url: String,
        token: String,
    ) -> Result<(), AuthrError> {
        self.0.lock().unwrap().push((url, token));
        Ok(())
    }
}

// -------------------- Test Helpers --------------------

macro_rules! app_with_sender {
    ($database:expr, $sender:expr) => {{
        let mut auth_config = config(true, authr::core::auth::SocialProviders::new(vec![]));
        auth_config.email_and_password = EmailAndPassword {
            reset_password_sender: Some(Arc::new($sender)),
            ..Default::default()
        };
        test_app!($database, auth_config)
    }};
}

macro_rules! create_test_user {
    ($app:expr) => {{
        let response = sign_up_user!($app, json!({
            "name": "Test User",
            "email": "test@example.com",
            "password": "password123"
        }));
        assert_eq!(response.status(), StatusCode::CREATED);
    }};
}

macro_rules! request_reset {
    ($app:expr, $email:expr, $redirect_to:expr) => {{
        let request = test::TestRequest::post()
            .uri("/api/auth/request-password-reset")
            .set_json(json!({ "email": $email, "redirectTo": $redirect_to }))
            .to_request();
        test::call_service(&$app, request).await
    }};
}

// -------------------- Request Password Reset --------------------

#[actix_web::test]
async fn password_reset_sends_a_link_and_does_not_reveal_user_existence() {
    init_tracing();
    let database = TestDatabase::default();
    let sender = RecordingResetSender::default();
    let app = app_with_sender!(database, sender.clone());
    create_test_user!(app);

    // ----- Request password reset
    let response = request_reset!(app, "test@example.com", "http://localhost:3000/reset");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["status"], true);
    assert_eq!(
        body["message"],
        "If this email exists in our system, check your email for the reset link"
    );

    // ----- Verify generated reset link
    assert!(sender.last_token().len() > 10);

    let url = url::Url::parse(&sender.last_url()).unwrap();
    assert!(url.path().ends_with(&sender.last_token()));
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "callbackURL")
            .unwrap()
            .1,
        "http://localhost:3000/reset"
    );

    // ----- Verify user existence isn't revealed
    let missing = request_reset!(app, "missing@example.com", "http://localhost:3000/reset");
    let missing_body: Value = test::read_body_json(missing).await;
    assert_eq!(missing_body["message"], body["message"]);
}

// -------------------- Password Reset Validation --------------------

#[actix_web::test]
async fn password_reset_rejects_untrusted_redirect_and_invalid_password() {
    init_tracing();
    let database = TestDatabase::default();
    let sender = RecordingResetSender::default();
    let app = app_with_sender!(database, sender);
    create_test_user!(app);

    // ----- Reject untrusted redirect URL
    let response = request_reset!(app, "test@example.com", "http://malicious.example/");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // ----- Reject password that violates policy
    let reset = test::TestRequest::post()
        .uri("/api/auth/reset-password")
        .set_json(json!({ "newPassword": "short", "token": "invalid" }))
        .to_request();
    let response = test::call_service(&app, reset).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -------------------- Password Reset Flow --------------------

#[actix_web::test]
async fn password_reset_changes_password_consumes_token_and_revokes_sessions() {
    init_tracing();
    let database = TestDatabase::default();
    let sender = RecordingResetSender::default();
    let app = app_with_sender!(database, sender.clone());
    create_test_user!(app);

    // ----- Create an existing session
    let sign_in = test::TestRequest::post()
        .uri("/api/auth/sign-in/email")
        .set_json(json!({ "email": "test@example.com", "password": "password123" }))
        .to_request();
    let sign_in_response = test::call_service(&app, sign_in).await;
    let cookie = sign_in_response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // ----- Request password reset
    let requested = request_reset!(app, "test@example.com", "http://localhost:3000");
    assert_eq!(requested.status(), StatusCode::OK);
    let token = sender.last_token();

    // ----- Reset password
    let reset = test::TestRequest::post()
        .uri("/api/auth/reset-password")
        .set_json(json!({ "newPassword": "new-password-123", "token": token }))
        .to_request();
    let response = test::call_service(&app, reset).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["status"], true);

    // ----- Reject reuse of reset token
    let replay = test::TestRequest::post()
        .uri("/api/auth/reset-password")
        .set_json(json!({ "newPassword": "other-password-123", "token": token }))
        .to_request();
    assert_eq!(
        test::call_service(&app, replay).await.status(),
        StatusCode::BAD_REQUEST
    );

    // ----- Verify old password is rejected
    let old_sign_in = test::TestRequest::post()
        .uri("/api/auth/sign-in/email")
        .set_json(json!({ "email": "test@example.com", "password": "password123" }))
        .to_request();
    assert_eq!(
        test::call_service(&app, old_sign_in).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // ----- Verify new password works
    let new_sign_in = test::TestRequest::post()
        .uri("/api/auth/sign-in/email")
        .set_json(json!({ "email": "test@example.com", "password": "new-password-123" }))
        .to_request();
    assert_eq!(
        test::call_service(&app, new_sign_in).await.status(),
        StatusCode::OK
    );

    // ----- Verify existing session was revoked
    let session_check = test::TestRequest::get()
        .uri("/api/auth/get-session")
        .insert_header((header::COOKIE, cookie))
        .to_request();
    let response = test::call_service(&app, session_check).await;
    let session: Value = test::read_body_json(response).await;
    assert_eq!(session, Value::Null);
}

// -------------------- Concurrent Password Resets --------------------

#[actix_web::test]
async fn concurrent_password_resets_using_one_token_only_allow_one_winner() {
    init_tracing();
    let database = TestDatabase::default();
    let sender = RecordingResetSender::default();
    let app = app_with_sender!(database, sender.clone());
    create_test_user!(app);

    // ----- Request password reset
    request_reset!(app, "test@example.com", "http://localhost:3000");
    let token = sender.last_token();

    // ----- Submit concurrent reset requests
    let first = test::TestRequest::post()
        .uri("/api/auth/reset-password")
        .set_json(json!({ "newPassword": "first-password-123", "token": token.clone() }))
        .to_request();
    let second = test::TestRequest::post()
        .uri("/api/auth/reset-password")
        .set_json(json!({ "newPassword": "second-password-123", "token": token }))
        .to_request();
    let (first, second) = tokio::join!(
        test::call_service(&app, first),
        test::call_service(&app, second),
    );
    let (first, second) = (first.status(), second.status());

    // ----- Verify exactly one request succeeds
    assert_eq!(
        [first, second]
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        [first, second]
            .iter()
            .filter(|status| **status == StatusCode::BAD_REQUEST)
            .count(),
        1
    );
}

// -------------------- Password Reset Callback --------------------

#[actix_web::test]
async fn reset_callback_accepts_callback_url_and_reports_expired_tokens() {
    init_tracing();
    let database = TestDatabase::default();
    let sender = RecordingResetSender::default();
    let app = app_with_sender!(database, sender.clone());
    create_test_user!(app);

    // ----- Request password reset
    request_reset!(
        app,
        "test@example.com",
        "http://localhost:3000/reset?source=email"
    );
    let token = sender.last_token();

    // ----- Verify valid token redirects with token
    let callback = test::TestRequest::get()
        .uri(&format!("/api/auth/reset-password/{token}?callbackURL=http%3A%2F%2Flocalhost%3A3000%2Freset%3Fsource%3Demail"))
        .to_request();
    let response = test::call_service(&app, callback).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("source=email"));
    assert!(location.contains(&format!("token={token}")));

    // ----- Expire token
    let store = database.to_authr_store();
    let mut verification = store
        .find_verification_by_identifier(&format!("reset-password:{token}"))
        .await
        .unwrap()
        .unwrap();
    verification.expires_at = Utc::now() - Duration::seconds(1);
    store.update_verification(verification).await.unwrap();

    // ----- Verify expired token redirects with error
    let callback = test::TestRequest::get()
        .uri(&format!(
            "/api/auth/reset-password/{token}?callbackURL=http%3A%2F%2Flocalhost%3A3000%2Freset"
        ))
        .to_request();
    let response = test::call_service(&app, callback).await;
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("error=INVALID_TOKEN"));
}

// -------------------- Verify Password --------------------

#[actix_web::test]
async fn verify_password_requires_session_and_checks_password() {
    init_tracing();
    let database = TestDatabase::default();
    let app = app_with_sender!(database, RecordingResetSender::default());
    create_test_user!(app);

    // ----- Build password verification request
    let verify = |password: &str, cookie: Option<String>| {
        let mut request = test::TestRequest::post().uri("/api/auth/verify-password");
        if let Some(cookie) = cookie {
            request = request.insert_header((header::COOKIE, cookie));
        }
        request
            .set_json(json!({ "password": password }))
            .to_request()
    };

    // ----- Reject unauthenticated request
    assert_eq!(
        test::call_service(&app, verify("password123", None))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // ----- Authenticate user
    let sign_in = test::TestRequest::post()
        .uri("/api/auth/sign-in/email")
        .set_json(json!({ "email": "test@example.com", "password": "password123" }))
        .to_request();
    let response = test::call_service(&app, sign_in).await;
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // ----- Accept correct password
    assert_eq!(
        test::call_service(&app, verify("password123", Some(cookie.clone())))
            .await
            .status(),
        StatusCode::OK
    );

    // ----- Reject incorrect password
    assert_eq!(
        test::call_service(&app, verify("wrong-password", Some(cookie)))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}
