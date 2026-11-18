pub mod adapters;
pub mod migrations;
pub mod models;
pub mod schema;
pub mod store;

// -----

use diesel::r2d2::{ConnectionManager, Pool, R2D2Connection};

fn create_pool<C>(
    database_url: &str,
) -> Result<Pool<ConnectionManager<C>>, Box<dyn std::error::Error + Send + Sync>>
where
    C: R2D2Connection + 'static,
{
    let manager = ConnectionManager::<C>::new(database_url);
    let pool = Pool::builder().build(manager)?;
    Ok(pool)
}
