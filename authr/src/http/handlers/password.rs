use actix_web::{HttpResponse, Responder, post};

#[post("/forgot-password")]
pub async fn forgot_password() -> impl Responder {
    // Generate a password reset token.
    //
    // Internally, authr:
    // - Checks whether the account exists.
    // - Generates a cryptographically secure token.
    // - Stores a protected representation of the token.
    // - Associates it with the user's email and an expiration time.
    //
    // The library does not send emails. It returns the reset URL/token
    // so the application can deliver it using its own email service.
    HttpResponse::NotImplemented()
}

#[post("/reset-password")]
pub async fn reset_password() -> impl Responder {
    // Validate the reset token and update the user's password.
    //
    // Internally, authr:
    // - Checks the token and its expiration.
    // - Hashes the new password using Argon2id.
    // - Updates the credential account.
    // - Invalidates the reset token.
    // - Optionally revokes existing sessions.
    HttpResponse::NotImplemented()
}
