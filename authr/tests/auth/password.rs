use actix_web::{
    http::{StatusCode, header},
    test,
};
use serde_json::{Value, json};

use authr::core::auth::SocialProviders;

use crate::common::{
    helpers::{call, config, config_with, request, session_cookie, test_app},
    mock::{RecordingPasswordResetSender, TestDatabase},
};

// -------------------- Password Reset --------------------

// ----- Request Password Reset

#[actix_web::test]
async fn password_reset_sends_a_link_and_does_not_reveal_user_existence() {
    let database = TestDatabase::default();
    let sender = RecordingPasswordResetSender::default();
    let app = test_app!(
        database,
        config_with(true, SocialProviders::new(vec![]), |config| {
            config.email_and_password.reset_password_sender =
                Some(std::sync::Arc::new(sender.clone()));
        })
    );

    // ----- Create User
    let created = call!(
        app,
        POST,
        "/api/auth/sign-up",
        json = json!({
            "name": "Test User",
            "email": "test@example.com",
            "password": "password123"
        })
    );
    assert_eq!(created.status(), StatusCode::CREATED);

    // ----- Request Password Reset
    let response = call!(
        app,
        POST,
        "/api/auth/request-password-reset",
        json = json!({
            "email": "test@example.com",
            "redirectTo": "http://localhost:3000/reset"
        })
    );
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["status"], true);
    assert_eq!(
        body["message"],
        "If this email exists in our system, check your email for the reset link"
    );

    // ----- Validate Reset Link
    let token = sender.token();
    assert!(token.len() > 10);

    let url = url::Url::parse(&sender.url()).unwrap();
    assert!(url.path().ends_with(&token));
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "callbackURL")
            .unwrap()
            .1,
        "http://localhost:3000/reset"
    );

    // ----- Verify User Enumeration Protection
    let missing = call!(
        app,
        POST,
        "/api/auth/request-password-reset",
        json = json!({
            "email": "missing@example.com",
            "redirectTo": "http://localhost:3000/reset"
        })
    );

    let missing_body: Value = test::read_body_json(missing).await;
    assert_eq!(missing_body["message"], body["message"]);
}

// ----- Reject Invalid Requests

#[actix_web::test]
async fn password_reset_rejects_untrusted_redirect_and_invalid_password() {
    let database = TestDatabase::default();
    let app = test_app!(database, config(true, SocialProviders::new(vec![])));

    // ----- Reject Untrusted Redirect
    let response = call!(
        app,
        POST,
        "/api/auth/request-password-reset",
        json = json!({
            "email": "test@example.com",
            "redirectTo": "http://malicious.example/"
        })
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // ----- Reject Invalid Password
    let response = call!(
        app,
        POST,
        "/api/auth/reset-password",
        json = json!({
            "newPassword": "short",
            "token": "invalid"
        })
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ----- Update Password and Revoke Sessions

#[actix_web::test]
async fn password_reset_changes_password_consumes_token_and_revokes_sessions() {
    let database = TestDatabase::default();
    let sender = RecordingPasswordResetSender::default();
    let app = test_app!(
        database,
        config_with(true, SocialProviders::new(vec![]), |config| {
            config.email_and_password.reset_password_sender =
                Some(std::sync::Arc::new(sender.clone()));
        })
    );

    // ----- Create User
    call!(
        app,
        POST,
        "/api/auth/sign-up",
        json = json!({
            "name": "Test User",
            "email": "test@example.com",
            "password": "password123"
        })
    );

    // ----- Create Session
    let sign_in = call!(
        app,
        POST,
        "/api/auth/sign-in/email",
        json = json!({
            "email": "test@example.com",
            "password": "password123"
        })
    );
    let cookie = session_cookie(sign_in.headers());

    // ----- Request Password Reset
    let requested = call!(
        app,
        POST,
        "/api/auth/request-password-reset",
        json = json!({
            "email": "test@example.com",
            "redirectTo": "http://localhost:3000"
        })
    );
    assert_eq!(requested.status(), StatusCode::OK);

    let token = sender.token();

    // ----- Reset Password
    let response = call!(
        app,
        POST,
        "/api/auth/reset-password",
        json = json!({
            "newPassword": "new-password-123",
            "token": token
        })
    );
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["status"], true);

    // ----- Reject Token Reuse
    let replay = call!(
        app,
        POST,
        "/api/auth/reset-password",
        json = json!({
            "newPassword": "other-password-123",
            "token": token
        })
    );
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

    // ----- Verify Password Change
    assert_eq!(
        call!(
            app,
            POST,
            "/api/auth/sign-in/email",
            json = json!({
                "email": "test@example.com",
                "password": "password123"
            })
        )
        .status(),
        StatusCode::UNAUTHORIZED
    );

    assert_eq!(
        call!(
            app,
            POST,
            "/api/auth/sign-in/email",
            json = json!({
                "email": "test@example.com",
                "password": "new-password-123"
            })
        )
        .status(),
        StatusCode::OK
    );

    // ----- Verify Session Revocation
    let session: Value = test::read_body_json(call!(
        app,
        GET,
        "/api/auth/get-session",
        headers = [(header::COOKIE, cookie)]
    ))
    .await;

    assert_eq!(session, Value::Null);
}

// ----- Concurrent Password Reset

#[actix_web::test]
async fn concurrent_password_resets_using_one_token_only_allow_one_winner() {
    let database = TestDatabase::default();
    let sender = RecordingPasswordResetSender::default();
    let app = test_app!(
        database,
        config_with(true, SocialProviders::new(vec![]), |config| {
            config.email_and_password.reset_password_sender =
                Some(std::sync::Arc::new(sender.clone()));
        })
    );

    // ----- Create User
    call!(
        app,
        POST,
        "/api/auth/sign-up",
        json = json!({
            "name": "Test User",
            "email": "test@example.com",
            "password": "password123"
        })
    );

    // ----- Request Password Reset
    call!(
        app,
        POST,
        "/api/auth/request-password-reset",
        json = json!({
            "email": "test@example.com",
            "redirectTo": "http://localhost:3000"
        })
    );

    let token = sender.token();

    // ----- Submit Concurrent Reset Requests
    let first = request!(
        POST,
        "/api/auth/reset-password",
        json = json!({
            "newPassword": "first-password-123",
            "token": token.clone()
        })
    )
    .to_request();

    let second = request!(
        POST,
        "/api/auth/reset-password",
        json = json!({
            "newPassword": "second-password-123",
            "token": token
        })
    )
    .to_request();

    let (first, second) = tokio::join!(
        test::call_service(&app, first),
        test::call_service(&app, second),
    );

    // ----- Verify Only One Request Succeeded
    let statuses = [first.status(), second.status()];

    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );

    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::BAD_REQUEST)
            .count(),
        1
    );
}

// ----- Reset Password Callback

#[actix_web::test]
async fn reset_callback_accepts_callback_url_and_reports_expired_tokens() {
    let database = TestDatabase::default();
    let sender = RecordingPasswordResetSender::default();
    let app = test_app!(
        database,
        config_with(true, SocialProviders::new(vec![]), |config| {
            config.email_and_password.reset_password_sender =
                Some(std::sync::Arc::new(sender.clone()));
        })
    );

    // ----- Create User
    call!(
        app,
        POST,
        "/api/auth/sign-up",
        json = json!({
            "name": "Test User",
            "email": "test@example.com",
            "password": "password123"
        })
    );

    // ----- Request Password Reset
    call!(
        app,
        POST,
        "/api/auth/request-password-reset",
        json = json!({
            "email": "test@example.com",
            "redirectTo": "http://localhost:3000/reset?source=email"
        })
    );

    let token = sender.token();

    // ----- Validate Reset Callback
    let response = call!(
        app,
        GET,
        &format!(
            "/api/auth/reset-password/{token}?callbackURL={}",
            url::form_urlencoded::byte_serialize(b"http://localhost:3000/reset?source=email")
                .collect::<String>()
        )
    );
    assert_eq!(response.status(), StatusCode::FOUND);

    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(location.contains("source=email"));
    assert!(location.contains(&format!("token={token}")));

    // ----- Reject Expired Token
    database
        .expire_verification(&format!("reset-password:{token}"))
        .await;

    let response = call!(
        app,
        GET,
        &format!(
            "/api/auth/reset-password/{token}?callbackURL=http%3A%2F%2Flocalhost%3A3000%2Freset"
        )
    );

    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(location.contains("error=INVALID_TOKEN"));
}

// -------------------- Password Verification --------------------

#[actix_web::test]
async fn verify_password_requires_session_and_checks_password() {
    let database = TestDatabase::default();
    let app = test_app!(database, config(true, SocialProviders::new(vec![])));

    // ----- Create User
    call!(
        app,
        POST,
        "/api/auth/sign-up",
        json = json!({
            "name": "Test User",
            "email": "test@example.com",
            "password": "password123"
        })
    );

    // ----- Require Session
    assert_eq!(
        call!(
            app,
            POST,
            "/api/auth/verify-password",
            json = json!({ "password": "password123" })
        )
        .status(),
        StatusCode::UNAUTHORIZED
    );

    // ----- Verify Correct Password
    let sign_in = call!(
        app,
        POST,
        "/api/auth/sign-in/email",
        json = json!({
            "email": "test@example.com",
            "password": "password123"
        })
    );
    let cookie = session_cookie(sign_in.headers());

    assert_eq!(
        call!(
            app,
            POST,
            "/api/auth/verify-password",
            json = json!({ "password": "password123" }),
            headers = [(header::COOKIE, cookie.clone())]
        )
        .status(),
        StatusCode::OK
    );

    // ----- Reject Incorrect Password
    assert_eq!(
        call!(
            app,
            POST,
            "/api/auth/verify-password",
            json = json!({ "password": "wrong-password" }),
            headers = [(header::COOKIE, cookie)]
        )
        .status(),
        StatusCode::BAD_REQUEST
    );
}
