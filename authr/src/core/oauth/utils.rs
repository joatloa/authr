use actix_web::HttpRequest;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use url::Url;

use crate::core::{auth::BaseUrl, error::AuthrError};

/// Builds the OAuth callback URL for the specified provider.
pub fn get_provider_callback_url(
    base_url: &BaseUrl,
    base_path: &str,
    req: &HttpRequest,
    provider_id: &str,
) -> Result<Url, AuthrError> {
    // ----- Resolve base URL
    let connection = req.connection_info();
    let mut url = base_url.resolve(Some(connection.host()), Some(connection.scheme()))?;

    // ----- Append callback path
    url.set_path(&format!(
        "{}/callback/{}",
        base_path.trim_end_matches('/'),
        provider_id
    ));

    Ok(url)
}

pub fn generate_pkce_challenge(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}
