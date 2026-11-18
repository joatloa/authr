use actix_web::{HttpResponse, Responder, post};

#[post("/sign-out")]
pub async fn sign_out() -> impl Responder {
    // Extract the session token from the request cookie.
    //
    // Revoke the session in the database so it can no longer be used.
    HttpResponse::NotImplemented()
}
