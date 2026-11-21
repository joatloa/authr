#![allow(unused)]

use authr::database::adapter::DieselDatabase;
use diesel::{
    Connection, MysqlConnection, RunQueryDsl, connection::SimpleConnection,
    deserialize::QueryableByName, sql_query, sql_types::Text,
};

#[derive(QueryableByName)]
struct TableName {
    #[diesel(sql_type = Text)]
    table_name: String,
}

pub fn reset_database() {
    let url =
        std::env::var("AUTHR_BENCH_DATABASE_URL").expect("AUTHR_BENCH_DATABASE_URL must be set");

    let mut connection =
        MysqlConnection::establish(&url).expect("Failed to connect to benchmark database");

    let tables = sql_query(
        "SELECT TABLE_NAME AS table_name
         FROM information_schema.tables
         WHERE table_schema = DATABASE()
         AND table_type = 'BASE TABLE'
         AND table_name != '__diesel_schema_migrations'",
    )
    .load::<TableName>(&mut connection)
    .expect("Failed to retrieve benchmark tables");

    connection
        .batch_execute("SET FOREIGN_KEY_CHECKS = 0")
        .expect("Failed to disable foreign key checks");

    for table in tables {
        let table_name = table.table_name.replace('`', "``");

        connection
            .batch_execute(&format!("TRUNCATE TABLE `{table_name}`"))
            .expect("Failed to truncate benchmark table");
    }

    connection
        .batch_execute("SET FOREIGN_KEY_CHECKS = 1")
        .expect("Failed to restore foreign key checks");
}

pub fn database() -> DieselDatabase {
    let url =
        std::env::var("AUTHR_BENCH_DATABASE_URL").expect("AUTHR_BENCH_DATABASE_URL must be set");

    DieselDatabase::from_url(&url).expect("Failed to initialize benchmark database")
}
