use authr::core::{Address, Authr};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut authr = Authr::new();

    authr.address(Address {
        host: "127.0.0.1".to_string(),
        port: 6767,
    });

    authr.run().await
}
