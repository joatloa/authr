use std::{env, error::Error};

use authr::core::builder::Authr;
use dotenvy::dotenv;

#[actix_web::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    dotenv().ok();

    let mut authr = Authr::new();

    authr
        .base_url("http://127.0.0.1:6767".to_string())
        .address("127.0.0.1:8080".parse().unwrap());

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    authr.database(&database_url)?;

    authr.run().await?;

    Ok(())
}
