use actix_web::cookie::{Cookie, SameSite, time::Duration};
use chrono::Utc;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

use crate::core::types::Session;

pub fn hash_token(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());

    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);

    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn get_session_cookie(session: &Session) -> Cookie<'static> {
    let mut cookie = Cookie::build("authr_session", session.token.clone())
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
