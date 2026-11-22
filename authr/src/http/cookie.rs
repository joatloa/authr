use actix_web::{
    HttpRequest,
    cookie::{Cookie, SameSite, time::Duration},
};
use chrono::Utc;

use crate::core::types::Session;

/// Name of the cookie used to store the user's session token.
pub const SESSION_COOKIE_NAME: &str = "authr_session";

/// Extracts the **raw** session token from the request's session cookie.
pub fn extract_session_token(request: &HttpRequest) -> Option<String> {
    request
        .cookie(SESSION_COOKIE_NAME)
        .map(|cookie| cookie.value().to_string())
}
pub fn build_session_cookie(session: &Session) -> Cookie<'static> {
    let mut cookie = Cookie::build(SESSION_COOKIE_NAME, session.token.clone())
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .finish();

    let max_age = (session.expires_at - Utc::now()).num_seconds();

    if max_age > 0 {
        cookie.set_max_age(Duration::seconds(max_age));
    }

    cookie
}

pub fn build_removal_session_cookie() -> Cookie<'static> {
    let mut cookie = Cookie::build(SESSION_COOKIE_NAME, "")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .finish();

    cookie.make_removal();

    cookie
}
