use actix_web::cookie::{Cookie, SameSite, time::Duration};
use chrono::Utc;

use crate::core::types::Session;

pub const SESSION_COOKIE_NAME: &str = "authr_session";

pub fn get_session_cookie(session: &Session) -> Cookie<'static> {
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

pub fn get_removal_session_cookie() -> Cookie<'static> {
    let mut cookie = Cookie::build(SESSION_COOKIE_NAME, "")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .finish();

    cookie.make_removal();
    cookie
}
