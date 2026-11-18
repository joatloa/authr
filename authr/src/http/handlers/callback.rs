use actix_web::{HttpResponse, Responder, get};

#[get("/callback/{provider}")]
pub async fn callback() -> impl Responder {
    // Complete the OAuth authorization flow.
    //
    // Internally, authr:
    // - Validates the state value against the one generated earlier.
    // - Validates PKCE, if used.
    // - Exchanges the authorization code for access tokens.
    // - Validates the OIDC ID token when applicable.
    // - Retrieves the user's provider identity.
    // - Finds an existing linked account or creates a new local user.
    // - Creates a local session.
    //
    // Important:
    // The provider's access token is NOT your application's session token.
    HttpResponse::NotImplemented()
}
