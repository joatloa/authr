/// Extract the cookie pair from a `Set-Cookie` header for use in a request.
pub(crate) fn session_cookie(headers: &actix_web::http::header::HeaderMap) -> String {
    headers
        .get(actix_web::http::header::SET_COOKIE)
        .expect("response should set a session cookie")
        .to_str()
        .expect("session cookie should be valid text")
        .split(';')
        .next()
        .expect("session cookie should contain a name and value")
        .to_string()
}
