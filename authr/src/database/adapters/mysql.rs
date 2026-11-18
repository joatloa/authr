use async_trait::async_trait;
use chrono::{Duration, Utc};
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, Pool},
};
use uuid::Uuid;

use diesel::mysql::MysqlConnection;

use crate::{
    core::{
        helpers::session::{generate_token, hash_token},
        types::{Account, Session, User},
    },
    database::{
        create_pool,
        migrations::run_pending_migrations,
        models::{NewAccount, NewSession, NewUser, SessionRow, UserRow},
        schema::{account, session, user},
        store::{
            AccountsStore, AuthDatabase, SessionsStore, StoreResult, UsersStore, VerificationStore,
        },
    },
};

pub type MysqlPool = Pool<ConnectionManager<MysqlConnection>>;

pub struct MysqlDatabase {
    pool: MysqlPool,
}

impl MysqlDatabase {
    pub fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }

    pub fn from_url(url: &str) -> StoreResult<Self> {
        let pool = create_pool::<MysqlConnection>(url)?;
        run_pending_migrations(&pool)?;

        Ok(Self::new(pool))
    }
}

// ----- Store implementation
#[async_trait]
impl UsersStore for MysqlDatabase {
    async fn create_user(&self, user: User) -> StoreResult<User> {
        let mut conn = self.pool.get()?;

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().naive_utc();
        let new_user = NewUser {
            id: &id,
            name: &user.name,
            email: &user.email,
            emailVerified: false,
            image: user.image.as_deref(),
            createdAt: now,
            updatedAt: now,
        };

        diesel::insert_into(user::table)
            .values(&new_user)
            .execute(&mut conn)?;
        let row = user::table
            .filter(user::id.eq(&id))
            .select(UserRow::as_select())
            .first::<UserRow>(&mut conn)?;

        Ok(User::from(row))
    }

    async fn find_user_by_email(&self, email: &str) -> StoreResult<Option<User>> {
        let mut conn = self.pool.get()?;

        let result = user::table
            .filter(user::email.eq(email))
            .select(UserRow::as_select())
            .first::<UserRow>(&mut conn)
            .optional()?;

        Ok(result.map(User::from))
    }
}

#[async_trait]
impl SessionsStore for MysqlDatabase {
    async fn create_session(&self, user_id: &str, remember_me: bool) -> StoreResult<Session> {
        let mut conn = self.pool.get()?;

        let id = Uuid::new_v4().to_string();
        let token = generate_token();
        let token_hash = hash_token(&token);
        let now = Utc::now().naive_utc();
        let duration = if remember_me {
            Duration::days(30)
        } else {
            Duration::days(1)
        };
        let expires_at = (Utc::now() + duration).naive_utc();
        let new_session = NewSession {
            id: &id,
            userId: user_id,
            tokenHash: &token_hash,
            expiresAt: expires_at,
            ipAddress: None,
            userAgent: None,
            createdAt: now,
            updatedAt: now,
        };

        diesel::insert_into(session::table)
            .values(&new_session)
            .execute(&mut conn)?;

        let row = session::table
            .filter(session::id.eq(&id))
            .select(SessionRow::as_select())
            .first::<SessionRow>(&mut conn)?;

        Ok(row.into_session(token))
    }
}

#[async_trait]
impl AccountsStore for MysqlDatabase {
    async fn link_account(&self, account_data: Account) -> StoreResult<()> {
        let mut conn = self.pool.get()?;

        let id = account_data.id.to_string();
        let user_id = account_data.user_id.to_string();
        let now = Utc::now().naive_utc();

        let new_account = NewAccount {
            id: &id,
            userId: &user_id,
            accountId: &account_data.account_id,
            providerId: &account_data.provider_id,
            accessToken: account_data.access_token.as_deref(),
            refreshToken: account_data.refresh_token.as_deref(),
            accessTokenExpiresAt: account_data.access_token_expires_at.map(|t| t.naive_utc()),
            refreshTokenExpiresAt: account_data.refresh_token_expires_at.map(|t| t.naive_utc()),
            scope: account_data.scope.as_deref(),
            idToken: account_data.id_token.as_deref(),
            passwordHash: account_data.password_hash.as_deref(),
            createdAt: account_data.created_at.naive_utc(),
            updatedAt: now,
        };

        diesel::insert_into(account::table)
            .values(&new_account)
            .execute(&mut conn)?;

        Ok(())
    }
}

#[async_trait]
impl VerificationStore for MysqlDatabase {}

impl AuthDatabase for MysqlDatabase {}
