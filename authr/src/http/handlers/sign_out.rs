use actix_web::{
    HttpRequest, HttpResponse, Responder,
    cookie::{Cookie, SameSite},
    post, web,
};
use serde::Deserialize;

use crate::{
    core::auth::AuthrData,
    database::store::{AuthDatabase, SessionQuery},
    http::utils::SESSION_COOKIE_NAME,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignOutRequest {
    /// The URL to redirect to after provider logout
    callback_url: Option<String>,
    /// Return the provider logout URL by redirecting
    #[serde(default = "default_redirect")]
    redirect: bool,
    /// State to pass to the provider logout endpoint
    state: Option<String>,
}
fn default_redirect() -> bool {
    true
}

#[post("/sign-out")]
pub async fn sign_out(
    data: web::Data<AuthrData>,
    body: web::Json<SignOutRequest>,
    request: HttpRequest,
) -> impl Responder {
    let SignOutRequest {
        callback_url: _callback_url,
        redirect: _redirect,
        state: _state,
    } = body.into_inner();

    // ----- Extract the session token from the request cookie
    let session_token = request
        .cookie(SESSION_COOKIE_NAME)
        .map(|cookie| cookie.value().to_string());

    // ----- Revoke the session
    if let Some(token) = session_token {
        if let Err(error) = data
            .database
            .delete_session(SessionQuery::Token(&token))
            .await
        {
            eprintln!("Failed to delete session: {error}");
            // We still need to delete the cookie so we don't return an error
        }
    }

    // ----- Clear the session cookie
    let mut cookie = Cookie::build(SESSION_COOKIE_NAME, "")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .finish();

    cookie.make_removal();

    // ----- Return the sign-out response
    HttpResponse::Ok().cookie(cookie).json(serde_json::json!({
        "success": true
    }))
}
