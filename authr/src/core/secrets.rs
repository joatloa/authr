use hkdf::Hkdf;
use sha2::Sha256;

pub struct AuthrSecrets {
    pub session: [u8; 32],
    pub encryption: [u8; 32],
    pub signing: [u8; 32],
}

pub fn derive_secrets(secret: &str) -> AuthrSecrets {
    let hkdf = Hkdf::<Sha256>::new(
        Some(b"authr"),
        secret.as_bytes(),
    );

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
