use argon2::Argon2;

use crate::core::auth::AuthrConfig;
use crate::database::adapter::DieselDatabase;

// ----- Providers
pub struct AuthrData {
    #[cfg(any(feature = "mysql", feature = "postgres", feature = "sqlite"))]
    pub database: DieselDatabase,
    pub config: AuthrConfig,
    pub argon: Argon2<'static>,
}
