use async_trait::async_trait;
use chrono::{Duration, Utc};
#[cfg(feature = "mysql")]
use diesel::mysql::MysqlConnection;
#[cfg(feature = "postgres")]
use diesel::pg::PgConnection;
#[cfg(feature = "sqlite")]
use diesel::sqlite::SqliteConnection;

use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, Pool},
};

use crate::database::{
    create_pool,
    store::{AccountFilter, UserFilter, VerificationFilter},
};
use crate::database::{migrations::run_pending_migrations, store::SessionFilter};
use crate::{
    core::{
        error::AuthrError,
        types::{Account, Session, User, Verification},
        utils::hash_str,
    },
    database::{
        models::{
            AccountRow, NewAccount, NewSession, NewUser, NewVerification, SessionRow, UserRow,
            VerificationRow,
        },
        schema::{account, session, user, verification},
        store::{AuthDatabase, StoreResult},
    },
};

#[derive(diesel::MultiConnection)]
pub enum AnyConnection {
    #[cfg(feature = "mysql")]
    Mysql(diesel::mysql::MysqlConnection),

    #[cfg(feature = "postgres")]
    Postgres(diesel::pg::PgConnection),

    #[cfg(feature = "sqlite")]
    Sqlite(diesel::sqlite::SqliteConnection),
}

// -------------------- Implementation --------------------
pub struct DieselDatabase {
    pool: Pool<ConnectionManager<AnyConnection>>,
}

impl DieselDatabase {
    pub fn new(pool: Pool<ConnectionManager<AnyConnection>>) -> Self {
        Self { pool }
    }
    pub fn from_url(url: &str) -> StoreResult<Self> {
        let pool = create_pool::<AnyConnection>(url)?;
        run_pending_migrations(&pool)?;

        Ok(Self::new(pool))
    }
}

#[async_trait]
impl AuthDatabase for DieselDatabase {
    // ----- Users
    async fn create_user(&self, mut user_data: User) -> StoreResult<User> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::UserCreationFailed)?;

        let now = Utc::now();
        user_data.created_at = now;
        user_data.updated_at = now;

        let new_user = NewUser {
            id: &user_data.id.to_string(),
            name: &user_data.name,
            email: &user_data.email,
            emailVerified: user_data.email_verified,
            image: user_data.image.as_deref(),
            createdAt: user_data.created_at.naive_utc(),
            updatedAt: user_data.updated_at.naive_utc(),
        };

        diesel::insert_into(user::table)
            .values(&new_user)
            .execute(&mut conn)
            .map_err(|_| AuthrError::UserCreationFailed)?;

        Ok(user_data)
    }
    async fn find_user(&self, filter: UserFilter<'_>) -> StoreResult<Option<User>> {
        let mut conn = self.pool.get().map_err(|_| AuthrError::UserLookupFailed)?;

        let row = match filter {
            UserFilter::Id(id) => user::table
                .filter(user::id.eq(id))
                .select(UserRow::as_select())
                .first::<UserRow>(&mut conn)
                .optional(),
            UserFilter::Email(email) => user::table
                .filter(user::email.eq(email))
                .select(UserRow::as_select())
                .first::<UserRow>(&mut conn)
                .optional(),
        }
        .map_err(|_| AuthrError::UserLookupFailed)?;

        Ok(row.map(User::from))
    }
    async fn update_user(&self, mut user_data: User) -> StoreResult<Option<User>> {
        let mut conn = self.pool.get().map_err(|_| AuthrError::UserUpdateFailed)?;

        let now = Utc::now();
        user_data.updated_at = now;

        let affected = diesel::update(user::table.filter(user::id.eq(&user_data.id.to_string())))
            .set((
                user::name.eq(&user_data.name),
                user::email.eq(&user_data.email),
                user::emailVerified.eq(user_data.email_verified),
                user::image.eq(user_data.image.as_deref()),
                user::updatedAt.eq(user_data.updated_at.naive_utc()),
            ))
            .execute(&mut conn)
            .map_err(|_| AuthrError::UserUpdateFailed)?;

        if affected == 0 {
            return Ok(None);
        }

        Ok(Some(user_data))
    }
    async fn delete_user(&self, filter: UserFilter<'_>) -> StoreResult<bool> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::UserDeletionFailed)?;

        let affected = match filter {
            UserFilter::Id(id) => {
                diesel::delete(user::table.filter(user::id.eq(id))).execute(&mut conn)
            }
            UserFilter::Email(email) => {
                diesel::delete(user::table.filter(user::email.eq(email))).execute(&mut conn)
            }
        }
        .map_err(|_| AuthrError::UserDeletionFailed)?;

        Ok(affected > 0)
    }
    // ----- Sessions
    async fn create_session(
        &self,
        mut session_data: Session,
        lifetime: Duration,
    ) -> StoreResult<Session> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::SessionCreationFailed)?;

        // Hash the raw token before persisting it.
        let token_hash = hash_str(&session_data.token);

        let now = Utc::now();
        session_data.created_at = now;
        session_data.updated_at = now;
        session_data.expires_at = now + lifetime;

        let new_session = NewSession {
            id: &session_data.id.to_string(),
            userId: &session_data.user_id.to_string(),
            tokenHash: &token_hash,
            expiresAt: session_data.expires_at.naive_utc(),
            ipAddress: session_data.ip_address.as_deref(),
            userAgent: session_data.user_agent.as_deref(),
            createdAt: session_data.created_at.naive_utc(),
            updatedAt: session_data.updated_at.naive_utc(),
        };

        diesel::insert_into(session::table)
            .values(&new_session)
            .execute(&mut conn)
            .map_err(|_| AuthrError::SessionCreationFailed)?;

        Ok(session_data)
    }
    async fn find_session(&self, filter: SessionFilter<'_>) -> StoreResult<Option<Session>> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::SessionLookupFailed)?;

        let row = match filter {
            SessionFilter::Token(token) => session::table
                .filter(session::tokenHash.eq(hash_str(token)))
                .select(SessionRow::as_select())
                .first::<SessionRow>(&mut conn)
                .optional(),
            SessionFilter::UserId(user_id) => session::table
                .filter(session::userId.eq(user_id))
                .select(SessionRow::as_select())
                .first::<SessionRow>(&mut conn)
                .optional(),
            _ => unreachable!(),
        }
        .map_err(|_| AuthrError::SessionLookupFailed)?;

        Ok(row.map(|row| {
            let mut session = Session::from(row);
            // The raw token cannot be recovered from its stored hash.
            session.token.clear();
            session
        }))
    }
    async fn find_sessions(&self, filter: SessionFilter<'_>) -> StoreResult<Vec<Session>> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::SessionLookupFailed)?;

        let row = match filter {
            SessionFilter::Token(token) => session::table
                .filter(session::tokenHash.eq(hash_str(token)))
                .select(SessionRow::as_select())
                .load::<SessionRow>(&mut conn),
            SessionFilter::UserId(user_id) => session::table
                .filter(session::userId.eq(user_id))
                .select(SessionRow::as_select())
                .load::<SessionRow>(&mut conn),
            SessionFilter::UserIdExcept {
                user_id,
                session_id,
            } => session::table
                .filter(session::userId.eq(user_id))
                .filter(session::id.ne(session_id))
                .select(SessionRow::as_select())
                .load::<SessionRow>(&mut conn),
        }
        .map_err(|_| AuthrError::SessionLookupFailed)?;

        Ok(row
            .into_iter()
            .map(|row| {
                let mut session = Session::from(row);
                // The raw token cannot be recovered from its stored hash.
                session.token.clear();
                session
            })
            .collect())
    }
    async fn update_session(&self, mut session_data: Session) -> StoreResult<Option<Session>> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::SessionUpdateFailed)?;

        let now = Utc::now();

        session_data.updated_at = now;

        let affected =
            diesel::update(session::table.filter(session::id.eq(&session_data.id.to_string())))
                .set((
                    session::expiresAt.eq(session_data.expires_at.naive_utc()),
                    session::ipAddress.eq(session_data.ip_address.as_deref()),
                    session::userAgent.eq(session_data.user_agent.as_deref()),
                    session::updatedAt.eq(session_data.updated_at.naive_utc()),
                ))
                .execute(&mut conn)
                .map_err(|_| AuthrError::SessionUpdateFailed)?;

        if affected == 0 {
            return Ok(None);
        }

        Ok(Some(session_data))
    }
    async fn delete_session(&self, filter: SessionFilter<'_>) -> StoreResult<bool> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::SessionDeletionFailed)?;

        let affected = match filter {
            SessionFilter::Token(token) => {
                let token_hash = hash_str(token);

                diesel::delete(session::table.filter(session::tokenHash.eq(token_hash)))
                    .execute(&mut conn)
            }
            SessionFilter::UserId(user_id) => {
                diesel::delete(session::table.filter(session::userId.eq(user_id)))
                    .execute(&mut conn)
            }
            SessionFilter::UserIdExcept {
                user_id,
                session_id,
            } => diesel::delete(
                session::table
                    .filter(session::userId.eq(user_id))
                    .filter(session::id.ne(session_id)),
            )
            .execute(&mut conn),
        }
        .map_err(|_| AuthrError::SessionDeletionFailed)?;

        Ok(affected > 0)
    }
    // ----- Accounts
    async fn create_account(&self, mut account_data: Account) -> StoreResult<Account> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::AccountCreationFailed)?;

        let now = Utc::now();
        account_data.created_at = now;
        account_data.updated_at = now;

        let new_account = NewAccount {
            id: &account_data.id.to_string(),
            userId: &account_data.user_id.to_string(),
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
            updatedAt: account_data.updated_at.naive_utc(),
        };

        diesel::insert_into(account::table)
            .values(&new_account)
            .execute(&mut conn)
            .map_err(|_| AuthrError::AccountCreationFailed)?;

        Ok(account_data)
    }
    async fn find_account(&self, filter: AccountFilter<'_>) -> StoreResult<Option<Account>> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::AccountLookupFailed)?;

        let row = match filter {
            AccountFilter::Id(id) => account::table
                .filter(account::id.eq(id))
                .select(AccountRow::as_select())
                .first::<AccountRow>(&mut conn)
                .optional(),
            AccountFilter::Provider {
                provider_id,
                account_id,
            } => account::table
                .filter(account::providerId.eq(provider_id))
                .filter(account::accountId.eq(account_id))
                .select(AccountRow::as_select())
                .first::<AccountRow>(&mut conn)
                .optional(),
            AccountFilter::UserId(user_id) => account::table
                .filter(account::userId.eq(user_id))
                .select(AccountRow::as_select())
                .first::<AccountRow>(&mut conn)
                .optional(),
        }
        .map_err(|_| AuthrError::AccountLookupFailed)?;

        Ok(row.map(Account::from))
    }
    async fn find_accounts(&self, filter: AccountFilter<'_>) -> StoreResult<Vec<Account>> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::AccountLookupFailed)?;

        let row = match filter {
            AccountFilter::Id(id) => account::table
                .filter(account::id.eq(id))
                .select(AccountRow::as_select())
                .load::<AccountRow>(&mut conn),
            AccountFilter::Provider {
                provider_id,
                account_id,
            } => account::table
                .filter(account::providerId.eq(provider_id))
                .filter(account::accountId.eq(account_id))
                .select(AccountRow::as_select())
                .load::<AccountRow>(&mut conn),
            AccountFilter::UserId(user_id) => account::table
                .filter(account::userId.eq(user_id))
                .select(AccountRow::as_select())
                .load::<AccountRow>(&mut conn),
        }
        .map_err(|_| AuthrError::AccountLookupFailed)?;

        Ok(row.into_iter().map(Account::from).collect())
    }
    async fn update_account(&self, mut account_data: Account) -> StoreResult<Option<Account>> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::AccountUpdateFailed)?;

        let now = Utc::now();
        account_data.updated_at = now;

        let affected =
            diesel::update(account::table.filter(account::id.eq(&account_data.id.to_string())))
                .set((
                    account::userId.eq(account_data.user_id.to_string()),
                    account::accountId.eq(&account_data.account_id),
                    account::providerId.eq(&account_data.provider_id),
                    account::accessToken.eq(account_data.access_token.as_deref()),
                    account::refreshToken.eq(account_data.refresh_token.as_deref()),
                    account::accessTokenExpiresAt
                        .eq(account_data.access_token_expires_at.map(|t| t.naive_utc())),
                    account::refreshTokenExpiresAt
                        .eq(account_data.refresh_token_expires_at.map(|t| t.naive_utc())),
                    account::scope.eq(account_data.scope.as_deref()),
                    account::idToken.eq(account_data.id_token.as_deref()),
                    account::passwordHash.eq(account_data.password_hash.as_deref()),
                    account::updatedAt.eq(account_data.updated_at.naive_utc()),
                ))
                .execute(&mut conn)
                .map_err(|_| AuthrError::AccountUpdateFailed)?;

        if affected == 0 {
            return Ok(None);
        }

        Ok(Some(account_data))
    }
    async fn delete_account(&self, filter: AccountFilter<'_>) -> StoreResult<bool> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::AccountDeletionFailed)?;

        let affected = match filter {
            AccountFilter::Id(id) => {
                diesel::delete(account::table.filter(account::id.eq(id))).execute(&mut conn)
            }
            AccountFilter::Provider {
                provider_id,
                account_id,
            } => diesel::delete(
                account::table
                    .filter(account::providerId.eq(provider_id))
                    .filter(account::accountId.eq(account_id)),
            )
            .execute(&mut conn),
            AccountFilter::UserId(user_id) => {
                diesel::delete(account::table.filter(account::userId.eq(user_id)))
                    .execute(&mut conn)
            }
        }
        .map_err(|_| AuthrError::AccountDeletionFailed)?;

        Ok(affected > 0)
    }
    // ----- Verification
    async fn create_verification(
        &self,
        mut verification_data: Verification,
    ) -> StoreResult<Verification> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::VerificationCreationFailed)?;

        let now = Utc::now();
        verification_data.created_at = now;
        verification_data.updated_at = now;

        let new_verification = NewVerification {
            id: &verification_data.id.to_string(),
            identifier: &verification_data.identifier,
            value: &verification_data.value,
            expiresAt: verification_data.expires_at.naive_utc(),
            createdAt: verification_data.created_at.naive_utc(),
            updatedAt: verification_data.updated_at.naive_utc(),
        };
        diesel::insert_into(verification::table)
            .values(&new_verification)
            .execute(&mut conn)
            .map_err(|_| AuthrError::VerificationCreationFailed)?;

        Ok(verification_data)
    }
    async fn find_verification(
        &self,
        filter: VerificationFilter<'_>,
    ) -> StoreResult<Option<Verification>> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::VerificationLookupFailed)?;

        let row = match filter {
            VerificationFilter::Id(id) => verification::table
                .filter(verification::id.eq(id))
                .select(VerificationRow::as_select())
                .first::<VerificationRow>(&mut conn)
                .optional(),
            VerificationFilter::Identifier(identifier) => verification::table
                .filter(verification::identifier.eq(identifier))
                .select(VerificationRow::as_select())
                .first::<VerificationRow>(&mut conn)
                .optional(),
        }
        .map_err(|_| AuthrError::VerificationLookupFailed)?;

        Ok(row.map(Verification::from))
    }
    async fn update_verification(
        &self,
        mut verification_data: Verification,
    ) -> StoreResult<Option<Verification>> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::VerificationUpdateFailed)?;

        let now = Utc::now();
        verification_data.updated_at = now;

        let affected = diesel::update(
            verification::table.filter(verification::id.eq(&verification_data.id.to_string())),
        )
        .set((
            verification::identifier.eq(&verification_data.identifier),
            verification::value.eq(&verification_data.value),
            verification::expiresAt.eq(verification_data.expires_at.naive_utc()),
            verification::updatedAt.eq(verification_data.updated_at.naive_utc()),
        ))
        .execute(&mut conn)
        .map_err(|_| AuthrError::VerificationUpdateFailed)?;

        if affected == 0 {
            return Ok(None);
        }

        Ok(Some(verification_data))
    }
    async fn delete_verification(&self, filter: VerificationFilter<'_>) -> StoreResult<bool> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::VerificationDeletionFailed)?;

        let affected = match filter {
            VerificationFilter::Id(id) => {
                diesel::delete(verification::table.filter(verification::id.eq(id)))
                    .execute(&mut conn)
            }
            VerificationFilter::Identifier(identifier) => {
                diesel::delete(verification::table.filter(verification::identifier.eq(identifier)))
                    .execute(&mut conn)
            }
        }
        .map_err(|_| AuthrError::VerificationDeletionFailed)?;

        Ok(affected > 0)
    }
    async fn consume_verification(&self, identifier: &str) -> StoreResult<Option<Verification>> {
        let mut conn = self
            .pool
            .get()
            .map_err(|_| AuthrError::VerificationConsumptionFailed)?;

        match &mut *conn {
            #[cfg(feature = "mysql")]
            AnyConnection::Mysql(conn) => consume_verification_mysql(conn, identifier),

            #[cfg(feature = "postgres")]
            AnyConnection::Postgres(conn) => consume_verification_postgres(conn, identifier),

            #[cfg(feature = "sqlite")]
            AnyConnection::Sqlite(conn) => consume_verification_sqlite(conn, identifier),
        }
        .map_err(|_| AuthrError::VerificationConsumptionFailed)
    }
}

// ----- Helpers
#[cfg(feature = "mysql")]
fn consume_verification_mysql(
    conn: &mut MysqlConnection,
    identifier: &str,
) -> QueryResult<Option<Verification>> {
    conn.transaction(|conn| {
        let row = verification::table
            .filter(verification::identifier.eq(identifier))
            .for_update()
            .first::<VerificationRow>(conn)
            .optional()?;

        let Some(row) = row else {
            return Ok(None);
        };

        diesel::delete(verification::table.filter(verification::id.eq(&row.id))).execute(conn)?;

        Ok(Some(Verification::from(row)))
    })
}

#[cfg(feature = "postgres")]
fn consume_verification_postgres(
    conn: &mut PgConnection,
    identifier: &str,
) -> QueryResult<Option<Verification>> {
    conn.transaction(|conn| {
        let row = verification::table
            .filter(verification::identifier.eq(identifier))
            .for_update()
            .first::<VerificationRow>(conn)
            .optional()?;

        let Some(row) = row else {
            return Ok(None);
        };

        diesel::delete(verification::table.filter(verification::id.eq(&row.id))).execute(conn)?;

        Ok(Some(Verification::from(row)))
    })
}

#[cfg(feature = "sqlite")]
fn consume_verification_sqlite(
    conn: &mut SqliteConnection,
    identifier: &str,
) -> QueryResult<Option<Verification>> {
    conn.immediate_transaction(|conn| {
        let row = verification::table
            .filter(verification::identifier.eq(identifier))
            .first::<VerificationRow>(conn)
            .optional()?;

        let Some(row) = row else {
            return Ok(None);
        };

        diesel::delete(verification::table.filter(verification::id.eq(&row.id))).execute(conn)?;

        Ok(Some(Verification::from(row)))
    })
}
