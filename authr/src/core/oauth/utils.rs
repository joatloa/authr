use actix_web::HttpRequest;
use url::Url;

use crate::core::{auth::BaseUrl, error::AuthrError};

pub fn get_provider_callback_url(
    base_url: &BaseUrl,
    base_path: &str,
    _req: &HttpRequest,
    provider_id: &str,
) -> Result<Url, AuthrError> {
    let base = match base_url {
        BaseUrl::Link { host } => host.clone(),
        BaseUrl::List { .. } => unimplemented!(),
    };

    let mut url = Url::parse(&base).map_err(|_| AuthrError::Internal)?;

    url.set_path(&format!(
        "{}/callback/{}",
        base_path.trim_end_matches('/'),
        provider_id
    ));

    Ok(url)
}

pub fn generate_pkce_challenge(verifier: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
