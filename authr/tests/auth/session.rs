use actix_web::{
    http::{StatusCode, header},
    test,
};
use serde_json::{Value, json};

use crate::common::{
    helpers::{call, expire_session, seed_session, seed_user, test_app},
    log::init_tracing,
    mock::TestDatabase,
};

// -------------------- Get Session --------------------

#[actix_web::test]
async fn get_session_returns_current_session_and_user() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();

    let user = seed_user(&database, "Test User", "test@example.com").await;
    let session = seed_session(&database, user.id).await;

    let app = test_app!(database);

    let response = call!(
        app,
        GET,
        "/api/auth/get-session",
        headers = [(header::COOKIE, format!("authr_session={}", session.token))]
    );

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;

    println!("{body:#}");

    assert_eq!(body["session"]["id"], session.id.to_string());
    assert_eq!(body["session"]["userId"], user.id.to_string());
    assert_eq!(body["user"]["id"], user.id.to_string());

    // The raw token must never be returned from the database.
    assert_eq!(body["session"]["token"], "");
}

#[actix_web::test]
async fn get_session_returns_null_without_cookie() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let response = call!(app, GET, "/api/auth/get-session");

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, Value::Null);
}

#[actix_web::test]
async fn get_session_returns_null_and_deletes_expired_session() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;
    let session = expire_session(&database, seed_session(&database, user.id).await).await;
    let token = session.token.clone();

    let app = test_app!(database);
    let store = database.to_authr_store();

    let response = call!(
        app,
        GET,
        "/api/auth/get-session",
        headers = [(header::COOKIE, format!("authr_session={token}"))]
    );

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, Value::Null);

    // ----- Check Session from Database
    let stored_session = store.find_session_by_token(&token).await.unwrap();

    assert!(stored_session.is_none());
}

// -------------------- List Sessions --------------------

#[actix_web::test]
async fn list_sessions_returns_all_active_user_sessions() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;

    let first = seed_session(&database, user.id).await;
    let second = seed_session(&database, user.id).await;
    let third = seed_session(&database, user.id).await;

    let expired = expire_session(&database, seed_session(&database, user.id).await).await;

    let app = test_app!(database);

    let response = call!(
        app,
        GET,
        "/api/auth/list-sessions",
        headers = [(header::COOKIE, format!("authr_session={}", first.token))]
    );

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Response
    let body: Vec<Value> = test::read_body_json(response).await;

    assert_eq!(body.len(), 3);

    let session_ids: Vec<String> = body
        .iter()
        .map(|session| session["id"].as_str().unwrap().to_string())
        .collect();

    assert!(session_ids.contains(&first.id.to_string()));
    assert!(session_ids.contains(&second.id.to_string()));
    assert!(session_ids.contains(&third.id.to_string()));
    assert!(!session_ids.contains(&expired.id.to_string()));
}

#[actix_web::test]
async fn list_sessions_rejects_unauthenticated_request() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let response = call!(app, GET, "/api/auth/list-sessions");

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -------------------- Revoke Session --------------------

#[actix_web::test]
async fn revoke_session_deletes_target_session() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;

    let current = seed_session(&database, user.id).await;
    let target = seed_session(&database, user.id).await;
    let target_token = target.token.clone();

    let app = test_app!(database);
    let store = database.to_authr_store();

    let response = call!(
        app,
        POST,
        "/api/auth/revoke-session",
        json = json!({
            "token": target_token
        }),
        headers = [(header::COOKIE, format!("authr_session={}", current.token))]
    );

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, json!({ "success": true }));

    // ----- Check Target Session from Database
    let target_session = store.find_session_by_token(&target_token).await.unwrap();

    assert!(target_session.is_none());

    // ----- Check Current Session from Database
    let current_session = store.find_session_by_token(&current.token).await.unwrap();

    assert!(current_session.is_some());
}

#[actix_web::test]
async fn revoke_session_rejects_another_users_session() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();

    let first_user = seed_user(&database, "Test User", "test@example.com").await;
    let second_user = seed_user(&database, "Another User", "another@example.com").await;

    let current = seed_session(&database, first_user.id).await;
    let target = seed_session(&database, second_user.id).await;

    let app = test_app!(database);
    let store = database.to_authr_store();

    let response = call!(
        app,
        POST,
        "/api/auth/revoke-session",
        json = json!({
            "token": target.token
        }),
        headers = [(header::COOKIE, format!("authr_session={}", current.token))]
    );

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // ----- Check Target Session from Database
    let target_session = store.find_session_by_token(&target.token).await.unwrap();

    assert!(target_session.is_some());
}

#[actix_web::test]
async fn revoke_session_returns_not_found_for_unknown_token() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;
    let current = seed_session(&database, user.id).await;

    let app = test_app!(database);

    let response = call!(
        app,
        POST,
        "/api/auth/revoke-session",
        json = json!({
            "token": "unknown-session-token"
        }),
        headers = [(header::COOKIE, format!("authr_session={}", current.token))]
    );

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// -------------------- Revoke All Sessions --------------------

#[actix_web::test]
async fn revoke_sessions_deletes_all_user_sessions_and_clears_cookie() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;

    let first = seed_session(&database, user.id).await;
    let second = seed_session(&database, user.id).await;
    let third = seed_session(&database, user.id).await;

    let first_token = first.token.clone();
    let second_token = second.token.clone();
    let third_token = third.token.clone();

    let app = test_app!(database);
    let store = database.to_authr_store();

    let response = call!(
        app,
        POST,
        "/api/auth/revoke-sessions",
        headers = [(header::COOKIE, format!("authr_session={}", first.token))]
    );

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Cookie
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();

    assert!(set_cookie.contains("authr_session="));
    assert!(set_cookie.contains("Max-Age=0"));

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, json!({ "success": true }));

    // ----- Check Sessions from Database
    for token in [&first_token, &second_token, &third_token] {
        let session = store.find_session_by_token(token).await.unwrap();

        assert!(session.is_none());
    }
}

#[actix_web::test]
async fn revoke_sessions_rejects_unauthenticated_request() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let response = call!(app, POST, "/api/auth/revoke-sessions");

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -------------------- Revoke Other Sessions --------------------

#[actix_web::test]
async fn revoke_other_sessions_preserves_current_session() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;

    let current = seed_session(&database, user.id).await;
    let second = seed_session(&database, user.id).await;
    let third = seed_session(&database, user.id).await;

    let second_token = second.token.clone();
    let third_token = third.token.clone();

    let app = test_app!(database);
    let store = database.to_authr_store();

    let response = call!(
        app,
        POST,
        "/api/auth/revoke-other-sessions",
        headers = [(header::COOKIE, format!("authr_session={}", current.token))]
    );

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, json!({ "success": true }));

    // ----- Check Current Session from Database
    let current_session = store.find_session_by_token(&current.token).await.unwrap();

    assert!(current_session.is_some());

    // ----- Check Other Sessions from Database
    let second_session = store.find_session_by_token(&second_token).await.unwrap();

    let third_session = store.find_session_by_token(&third_token).await.unwrap();

    assert!(second_session.is_none());
    assert!(third_session.is_none());
}

#[actix_web::test]
async fn revoke_other_sessions_does_not_revoke_another_users_sessions() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = seed_user(&database, "Test User", "test@example.com").await;

    let other_user = seed_user(&database, "Another User", "another@example.com").await;

    let current = seed_session(&database, user.id).await;
    let other_user_session = seed_session(&database, other_user.id).await;

    let app = test_app!(database);
    let store = database.to_authr_store();

    // ----- Send Request
    let response = call!(
        app,
        POST,
        "/api/auth/revoke-other-sessions",
        headers = [(header::COOKIE, format!("authr_session={}", current.token))]
    );

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Other User's Session from Database
    let stored_session = store
        .find_session_by_token(&other_user_session.token)
        .await
        .unwrap();

    assert!(stored_session.is_some());
}
