use diesel::MysqlConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

pub fn run_pending_migrations(
    pool: &Pool<ConnectionManager<MysqlConnection>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut connection = pool.get()?;

    connection.run_pending_migrations(MIGRATIONS)?;

    Ok(())
}
