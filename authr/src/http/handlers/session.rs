use actix_web::{HttpResponse, Responder, get};

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
