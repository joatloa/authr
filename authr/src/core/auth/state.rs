use crate::{core::auth::AuthrConfig, database::store::AuthDatabase};
use argon2::Argon2;

// ----- Providers
pub struct AuthrData<D: AuthDatabase + 'static> {
    pub database: D,
    pub config: AuthrConfig,
    pub argon: Argon2<'static>,
}
