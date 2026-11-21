use async_trait::async_trait;
use chrono::Duration;

use crate::core::{
    error::AuthrError,
    types::{Account, Session, User, Verification},
};

pub type StoreResult<T> = Result<T, AuthrError>;

// -------------------- Queries --------------------

pub enum UserFilter<'a> {
    Id(&'a str),
    Email(&'a str),
}

pub enum SessionFilter<'a> {
    Token(&'a str),
    UserId(&'a str),
    UserIdExcept {
        user_id: &'a str,
        session_id: &'a str,
    },
}

pub enum AccountFilter<'a> {
    Id(&'a str),
    Provider {
        provider_id: &'a str,
        account_id: &'a str,
    },
    UserId(&'a str),
}

pub enum VerificationFilter<'a> {
    Id(&'a str),
    Identifier(&'a str),
}

// -------------------- Store --------------------

#[async_trait]
pub trait AuthDatabase: Send + Sync {
    // ----- Users
    async fn create_user(&self, user: User) -> StoreResult<User>;
    async fn find_user(&self, query: UserFilter<'_>) -> StoreResult<Option<User>>;
    async fn update_user(&self, user: User) -> StoreResult<Option<User>>;
    async fn delete_user(&self, query: UserFilter<'_>) -> StoreResult<bool>;

    // ----- Sessions
    async fn create_session(&self, session: Session, lifetime: Duration) -> StoreResult<Session>;
    async fn find_session(&self, query: SessionFilter<'_>) -> StoreResult<Option<Session>>;
    async fn find_sessions(&self, query: SessionFilter<'_>) -> StoreResult<Vec<Session>>;
    async fn update_session(&self, session: Session) -> StoreResult<Option<Session>>;
    async fn delete_session(&self, query: SessionFilter<'_>) -> StoreResult<bool>;

    // ----- Accounts
    async fn create_account(&self, account: Account) -> StoreResult<Account>;
    async fn find_account(&self, query: AccountFilter<'_>) -> StoreResult<Option<Account>>;
    async fn find_accounts(&self, query: AccountFilter<'_>) -> StoreResult<Vec<Account>>;
    async fn update_account(&self, account: Account) -> StoreResult<Option<Account>>;
    async fn delete_account(&self, query: AccountFilter<'_>) -> StoreResult<bool>;

    // ----- Verifications
    async fn create_verification(&self, verification: Verification) -> StoreResult<Verification>;
    async fn find_verification(
        &self,
        query: VerificationFilter<'_>,
    ) -> StoreResult<Option<Verification>>;
    async fn update_verification(
        &self,
        verification: Verification,
    ) -> StoreResult<Option<Verification>>;
    async fn delete_verification(&self, query: VerificationFilter<'_>) -> StoreResult<bool>;
    async fn consume_verification(&self, identifier: &str) -> StoreResult<Option<Verification>>;
}
