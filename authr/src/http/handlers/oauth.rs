use actix_web::{HttpResponse, Responder, get, post};

#[get("/{provider}")]
pub async fn provider() -> impl Responder {
    // Start the OAuth authorization flow.
    //
    // Internally, authr:
    // - Finds the registered provider.
    // - Generates a random state value to prevent CSRF attacks.
    // - Generates PKCE values when supported.
    // - Temporarily stores the state and PKCE verifier.
    // - Builds the provider's authorization URL.
    //
    // The returned URL points to Google, GitHub, Discord, etc.
    HttpResponse::NotImplemented()
}

#[get("/{provider}/callback")]
pub async fn provider_callback() -> impl Responder {
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

#[post("/link/{provider}")]
pub async fn link_provider() -> impl Responder {
    // Start linking an OAuth provider to the currently authenticated user.
    //
    // Unlike normal OAuth login, this operation must NOT create a new
    // local user. It associates the provider identity with user.id.
    //
    // Internally, authr:
    // - Generates state and PKCE values.
    // - Stores the initiating user's ID with the OAuth transaction.
    // - Builds the provider's authorization URL.
    HttpResponse::NotImplemented()
}
