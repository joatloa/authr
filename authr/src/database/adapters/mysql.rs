use diesel::mysql::MysqlConnection;
use diesel::r2d2::{ConnectionManager, Pool};

use crate::database::migrations::run_pending_migrations;
use crate::database::{
    create_pool,
    store::{AccountsStore, AuthDatabase, SesssionsStore, UsersStore, VerificationStore},
};

pub type MysqlPool = Pool<ConnectionManager<MysqlConnection>>;

pub struct MysqlDatabase {
    pool: MysqlPool,
}

impl MysqlDatabase {
    pub fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }

    pub fn from_url(url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let pool = create_pool::<MysqlConnection>(url)?;
        run_pending_migrations(&pool)?;
        Ok(Self::new(pool))
    }
}

// ----- Store Implementation

impl UsersStore for MysqlDatabase {}
impl AccountsStore for MysqlDatabase {}
impl SesssionsStore for MysqlDatabase {}
impl VerificationStore for MysqlDatabase {}

impl AuthDatabase for MysqlDatabase {}
