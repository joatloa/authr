use async_trait::async_trait;
use chrono::Duration;

use crate::core::{
    error::AuthrError,
    types::{Account, Session, User, Verification},
};

/// Result returned by Authr persistence operations.
pub type StoreResult<T> = Result<T, AuthrError>;

// -------------------- Queries --------------------

pub enum UserFilter<'a> {
    Id(&'a str),
    Email(&'a str),
}

pub enum SessionFilter<'a> {
    /// Match a session using its raw token.
    Token(&'a str),
    UserId(&'a str),
    UserIdExcept {
        user_id: &'a str,
        /// Session to exclude.
        session_id: &'a str,
    },
}

pub enum AccountFilter<'a> {
    Id(&'a str),
    Provider {
        provider_id: &'a str,
        /// Account ID assigned by the provider.
        account_id: &'a str,
    },
    UserId(&'a str),
}

pub enum VerificationFilter<'a> {
    Id(&'a str),
    Identifier(&'a str),
}

// -------------------- Store --------------------

/// Persistence contract required by Authr's authentication flows.
#[async_trait]
pub trait AuthDatabase: Send + Sync {
    // ----- Users
    /// Inserts a user and returns the persisted value.
    async fn create_user(&self, user: User) -> StoreResult<User>;
    /// Finds one user matching the filter.
    async fn find_user(&self, query: UserFilter<'_>) -> StoreResult<Option<User>>;
    /// Updates a user by ID, returning `None` when it does not exist.
    async fn update_user(&self, user: User) -> StoreResult<Option<User>>;
    /// Deletes matching user records and reports whether any were removed.
    async fn delete_user(&self, query: UserFilter<'_>) -> StoreResult<bool>;

    // ----- Sessions
    /// Creates a session using the supplied lifetime from the current time.
    async fn create_session(&self, session: Session, lifetime: Duration) -> StoreResult<Session>;
    /// Finds one session matching the filter.
    async fn find_session(&self, query: SessionFilter<'_>) -> StoreResult<Option<Session>>;
    /// Finds all sessions matching the filter.
    async fn find_sessions(&self, query: SessionFilter<'_>) -> StoreResult<Vec<Session>>;
    /// Updates a session by ID, returning `None` when it does not exist.
    async fn update_session(&self, session: Session) -> StoreResult<Option<Session>>;
    /// Deletes matching sessions and reports whether any were removed.
    async fn delete_session(&self, query: SessionFilter<'_>) -> StoreResult<bool>;

    // ----- Accounts
    /// Inserts an account and returns the persisted value.
    async fn create_account(&self, account: Account) -> StoreResult<Account>;
    /// Finds one account matching the filter.
    async fn find_account(&self, query: AccountFilter<'_>) -> StoreResult<Option<Account>>;
    /// Finds all accounts matching the filter.
    async fn find_accounts(&self, query: AccountFilter<'_>) -> StoreResult<Vec<Account>>;
    /// Updates an account by ID, returning `None` when it does not exist.
    async fn update_account(&self, account: Account) -> StoreResult<Option<Account>>;
    /// Deletes matching accounts and reports whether any were removed.
    async fn delete_account(&self, query: AccountFilter<'_>) -> StoreResult<bool>;

    // ----- Verifications
    /// Inserts a verification and returns the persisted value.
    async fn create_verification(&self, verification: Verification) -> StoreResult<Verification>;
    /// Finds one verification matching the filter.
    async fn find_verification(
        &self,
        query: VerificationFilter<'_>,
    ) -> StoreResult<Option<Verification>>;
    /// Updates a verification by ID, returning `None` when it does not exist.
    async fn update_verification(
        &self,
        verification: Verification,
    ) -> StoreResult<Option<Verification>>;
    /// Deletes matching verifications and reports whether any were removed.
    async fn delete_verification(&self, query: VerificationFilter<'_>) -> StoreResult<bool>;
    /// Atomically returns and deletes the verification for an identifier.
    async fn consume_verification(&self, identifier: &str) -> StoreResult<Option<Verification>>;
}
