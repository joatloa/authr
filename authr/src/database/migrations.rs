use diesel::MysqlConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

use crate::core::error::AuthrError;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

pub fn run_pending_migrations(
    pool: &Pool<ConnectionManager<MysqlConnection>>,
) -> Result<(), AuthrError> {
    let mut connection = pool.get().map_err(|_| AuthrError::Internal)?;

    connection
        .run_pending_migrations(MIGRATIONS)
        .map_err(|_| AuthrError::Internal)?;

    Ok(())
}
