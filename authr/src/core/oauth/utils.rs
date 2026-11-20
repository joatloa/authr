use actix_web::HttpRequest;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use url::Url;

use crate::core::{auth::BaseUrl, error::AuthrError};

pub fn get_provider_callback_url(
    base_url: &BaseUrl,
    base_path: &str,
    req: &HttpRequest,
    provider_id: &str,
) -> Result<Url, AuthrError> {
    let base = match base_url {
        BaseUrl::Link { host } => host.clone(),

        BaseUrl::List {
            allowed_hosts,
            fallback,
        } => {
            let connection_info = req.connection_info();

            let host = connection_info.host();

            if !allowed_hosts.iter().any(|allowed| allowed == host) {
                fallback.clone()
            } else {
                format!("{}://{}", connection_info.scheme(), host)
            }
        }
    };

    let mut url = Url::parse(&base).map_err(|_| AuthrError::Internal)?;

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
