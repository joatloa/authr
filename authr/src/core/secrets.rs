use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct AuthrSecrets {
    pub session: [u8; 32],
    pub encryption: [u8; 32],
    pub signing: [u8; 32],
}

impl AuthrSecrets {
    pub fn hash_session_token(&self, token: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.session).expect("HMAC accepts keys of any length");

        mac.update(token.as_bytes());

        mac.finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

pub fn derive_secrets(secret: &str) -> AuthrSecrets {
    let hkdf = Hkdf::<Sha256>::new(Some(b"authr"), secret.as_bytes());

    let mut session = [0u8; 32];
    let mut encryption = [0u8; 32];
    let mut signing = [0u8; 32];

    hkdf.expand(b"session", &mut session)
        .expect("32 bytes is a valid HKDF output length");

    hkdf.expand(b"encryption", &mut encryption)
        .expect("32 bytes is a valid HKDF output length");

    hkdf.expand(b"signing", &mut signing)
        .expect("32 bytes is a valid HKDF output length");

    AuthrSecrets {
        session,
        encryption,
        signing,
    }
}
