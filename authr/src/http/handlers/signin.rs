use actix_web::{HttpResponse, Responder, post, web};
use serde::Deserialize;

#[derive(Deserialize)]
struct SigninRequest {
    email: String,
    password: String,
    remember_me: bool,
    callback_url: Option<String>,
}

#[post("/signin")]
pub async fn sign_in(body: web::Json<SigninRequest>) -> impl Responder {
    // Authenticate using email and password.
    //
    // Internally, authr:
    // - Finds the user and their credential account.
    // - Verifies the password hash.
    // - Creates a new session.
    // - Returns the session information.
    HttpResponse::NotImplemented()
}
