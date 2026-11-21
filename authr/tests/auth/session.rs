use actix_web::{
    App,
    http::{Method, StatusCode, header},
    test, web,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

use authr::{
    core::{
        auth::{AuthrContext, SocialProviders},
        types::{Session, User},
    },
    database::store::{AuthDatabase, SessionFilter},
    http::router,
};

use crate::common::{TestDatabase, config, init_tracing, test_app};

// -------------------- Helpers --------------------

async fn create_user(database: &TestDatabase) -> User {
    database
        .create_user(User::new(
            "Test User".to_string(),
            "test@example.com".to_string(),
            false,
            None,
        ))
        .await
        .unwrap()
}

async fn create_session(database: &TestDatabase, user_id: uuid::Uuid) -> Session {
    database
        .create_session(Session::new(user_id, None, None), Duration::days(1))
        .await
        .unwrap()
}

async fn create_expired_session(database: &TestDatabase, user_id: uuid::Uuid) -> Session {
    let mut session = create_session(database, user_id).await;
    session.expires_at = Utc::now() - Duration::seconds(60);

    database
        .update_session(session.clone())
        .await
        .unwrap()
        .unwrap()
}

fn authenticated_request(method: Method, uri: &str, token: &str) -> test::TestRequest {
    test::TestRequest::default()
        .method(method)
        .uri(uri)
        .insert_header((header::COOKIE, format!("authr_session={token}")))
}

// -------------------- Get Session --------------------

#[actix_web::test]
async fn get_session_returns_current_session_and_user() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();

    let user = create_user(&database).await;
    let session = create_session(&database, user.id).await;

    let app = test_app!(database);

    let request =
        authenticated_request(Method::GET, "/api/auth/get-session", &session.token).to_request();
    let response = test::call_service(&app, request).await;

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

    let request = test::TestRequest::get()
        .uri("/api/auth/get-session")
        .to_request();
    let response = test::call_service(&app, request).await;

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
    let user = create_user(&database).await;
    let session = create_expired_session(&database, user.id).await;
    let token = session.token.clone();

    let app = test_app!(database);

    let request = authenticated_request(Method::GET, "/api/auth/get-session", &token).to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, Value::Null);

    // ----- Check Session from Database
    let stored_session = database
        .find_session(SessionFilter::Token(&token))
        .await
        .unwrap();

    assert!(stored_session.is_none());
}

// -------------------- List Sessions --------------------

#[actix_web::test]
async fn list_sessions_returns_all_active_user_sessions() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = create_user(&database).await;

    let first = create_session(&database, user.id).await;
    let second = create_session(&database, user.id).await;
    let third = create_session(&database, user.id).await;

    let expired = create_expired_session(&database, user.id).await;

    let app = test_app!(database);

    let request =
        authenticated_request(Method::GET, "/api/auth/list-sessions", &first.token).to_request();
    let response = test::call_service(&app, request).await;

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

    let request = test::TestRequest::get()
        .uri("/api/auth/list-sessions")
        .to_request();
    let response = test::call_service(&app, request).await;

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -------------------- Revoke Session --------------------

#[actix_web::test]
async fn revoke_session_deletes_target_session() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = create_user(&database).await;

    let current = create_session(&database, user.id).await;
    let target = create_session(&database, user.id).await;
    let target_token = target.token.clone();

    let app = test_app!(database);

    let req_body = json!({
        "token": target_token
    });
    let request = authenticated_request(Method::POST, "/api/auth/revoke-session", &current.token)
        .set_json(req_body)
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, json!({ "success": true }));

    // ----- Check Target Session from Database
    let target_session = database
        .find_session(SessionFilter::Token(&target_token))
        .await
        .unwrap();

    assert!(target_session.is_none());

    // ----- Check Current Session from Database
    let current_session = database
        .find_session(SessionFilter::Token(&current.token))
        .await
        .unwrap();

    assert!(current_session.is_some());
}

#[actix_web::test]
async fn revoke_session_rejects_another_users_session() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();

    let first_user = create_user(&database).await;
    let second_user = database
        .create_user(User::new(
            "Another User".to_string(),
            "another@example.com".to_string(),
            false,
            None,
        ))
        .await
        .unwrap();

    let current = create_session(&database, first_user.id).await;
    let target = create_session(&database, second_user.id).await;

    let app = test_app!(database);

    let req_body = json!({
        "token": target.token
    });
    let request = authenticated_request(Method::POST, "/api/auth/revoke-session", &current.token)
        .set_json(req_body)
        .to_request();
    let response = test::call_service(&app, request).await;

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // ----- Check Target Session from Database
    let target_session = database
        .find_session(SessionFilter::Token(&target.token))
        .await
        .unwrap();

    assert!(target_session.is_some());
}

#[actix_web::test]
async fn revoke_session_returns_not_found_for_unknown_token() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = create_user(&database).await;
    let current = create_session(&database, user.id).await;

    let app = test_app!(database);

    let req_body = json!({
        "token": "unknown-session-token"
    });
    let request = authenticated_request(Method::POST, "/api/auth/revoke-session", &current.token)
        .set_json(req_body)
        .to_request();
    let response = test::call_service(&app, request).await;

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// -------------------- Revoke All Sessions --------------------

#[actix_web::test]
async fn revoke_sessions_deletes_all_user_sessions_and_clears_cookie() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = create_user(&database).await;

    let first = create_session(&database, user.id).await;
    let second = create_session(&database, user.id).await;
    let third = create_session(&database, user.id).await;

    let first_token = first.token.clone();
    let second_token = second.token.clone();
    let third_token = third.token.clone();

    let app = test_app!(database);

    let request =
        authenticated_request(Method::POST, "/api/auth/revoke-sessions", &first.token).to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Cookie
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    assert!(set_cookie.contains("authr_session="));
    assert!(set_cookie.contains("Max-Age=0"));

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, json!({ "success": true }));

    // ----- Check Sessions from Database
    for token in [&first_token, &second_token, &third_token] {
        let session = database
            .find_session(SessionFilter::Token(token))
            .await
            .unwrap();

        assert!(session.is_none());
    }
}

#[actix_web::test]
async fn revoke_sessions_rejects_unauthenticated_request() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let app = test_app!(database);

    let request = test::TestRequest::post()
        .uri("/api/auth/revoke-sessions")
        .to_request();
    let response = test::call_service(&app, request).await;

    // ----- Rejects
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -------------------- Revoke Other Sessions --------------------

#[actix_web::test]
async fn revoke_other_sessions_preserves_current_session() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = create_user(&database).await;

    let current = create_session(&database, user.id).await;
    let second = create_session(&database, user.id).await;
    let third = create_session(&database, user.id).await;

    let second_token = second.token.clone();
    let third_token = third.token.clone();

    let app = test_app!(database);

    let request = authenticated_request(
        Method::POST,
        "/api/auth/revoke-other-sessions",
        &current.token,
    )
    .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Response
    let body: Value = test::read_body_json(response).await;

    assert_eq!(body, json!({ "success": true }));

    // ----- Check Current Session from Database
    let current_session = database
        .find_session(SessionFilter::Token(&current.token))
        .await
        .unwrap();

    assert!(current_session.is_some());

    // ----- Check Other Sessions from Database
    let second_session = database
        .find_session(SessionFilter::Token(&second_token))
        .await
        .unwrap();

    let third_session = database
        .find_session(SessionFilter::Token(&third_token))
        .await
        .unwrap();

    assert!(second_session.is_none());
    assert!(third_session.is_none());
}

#[actix_web::test]
async fn revoke_other_sessions_does_not_revoke_another_users_sessions() {
    // ----- Setup
    init_tracing();

    let database = TestDatabase::default();
    let user = create_user(&database).await;

    let other_user = database
        .create_user(User::new(
            "Another User".to_string(),
            "another@example.com".to_string(),
            false,
            None,
        ))
        .await
        .unwrap();

    let current = create_session(&database, user.id).await;
    let other_user_session = create_session(&database, other_user.id).await;

    let app = test_app!(database);

    let request = authenticated_request(
        Method::POST,
        "/api/auth/revoke-other-sessions",
        &current.token,
    )
    .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    // ----- Check Other User's Session from Database
    let stored_session = database
        .find_session(SessionFilter::Token(&other_user_session.token))
        .await
        .unwrap();

    assert!(stored_session.is_some());
}
