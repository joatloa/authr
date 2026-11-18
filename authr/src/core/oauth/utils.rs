use url::Url;

use crate::core::error::AuthrError;

pub fn get_provider_callback_url(base_url: &str, provider_id: &str) -> Result<Url, AuthrError> {
    let mut url = Url::parse(base_url).map_err(|_| AuthrError::Internal)?;

    url.set_path(&format!("/api/auth/{provider_id}/callback"));
    url.set_query(None);
    url.set_fragment(None);

    Ok(url)
}

pub fn generate_pkce_challenge(verifier: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
