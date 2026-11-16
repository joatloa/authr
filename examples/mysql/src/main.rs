use std::{env, error::Error};

use authr::core::{Address, Authr};
use dotenvy::dotenv;

#[actix_web::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    dotenv().ok();

    let mut authr = Authr::new();

    authr.address(Address {
        host: "127.0.0.1".to_string(),
        port: 6767,
    });

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    authr.database(&database_url)?;

    authr.run().await?;

    Ok(())
}
