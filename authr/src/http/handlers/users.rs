use actix_web::{HttpResponse, Responder, get, post, web};
use serde::Deserialize;

#[derive(Deserialize)]
struct RegisterRequest {
    name: String,
    email: String,
    password: String,
    image: Option<String>,
    callback_url: Option<String>,
}

#[post("/register")]
pub async fn register(body: web::Json<RegisterRequest>) -> impl Responder {
    HttpResponse::NotImplemented()
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
    remember_me: bool,
    callback_url: Option<String>,
}

#[post("/login")]
pub async fn login(body: web::Json<LoginRequest>) -> impl Responder {
    // Authenticate using email and password.
    //
    // Internally, authr:
    // - Finds the user and their credential account.
    // - Verifies the password hash.
    // - Creates a new session.
    // - Returns the session information.
    HttpResponse::NotImplemented()
}

#[post("/logout")]
pub async fn logout() -> impl Responder {
    // Extract the session token from the request cookie.
    //
    // Revoke the session in the database so it can no longer be used.
    HttpResponse::NotImplemented()
}

#[get("/session")]
pub async fn session() -> impl Responder {
    // AuthenticatedUser is an Actix extractor provided by authr.
    //
    // Before this handler executes, it:
    // - Reads the session cookie.
    // - Validates the session.
    // - Checks its expiration.
    // - Retrieves the associated user.
    //
    // If authentication fails, the request is rejected.
    //
    // No additional database queries are needed here.
    HttpResponse::NotImplemented()
}
