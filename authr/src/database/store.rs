use async_trait::async_trait;

use crate::core::{
    error::AuthrError,
    types::{Account, Session, User, Verification},
};

pub type StoreResult<T> = Result<T, AuthrError>;

// -------------------- Queries --------------------

pub enum UserQuery<'a> {
    Id(&'a str),
    Email(&'a str),
}

pub enum SessionQuery<'a> {
    Token(&'a str),
    UserId(&'a str),
    UserIdExcept {
        user_id: &'a str,
        session_id: &'a str,
    },
}

pub enum AccountQuery<'a> {
    Id(&'a str),
    Provider {
        provider_id: &'a str,
        account_id: &'a str,
    },
    UserId(&'a str),
}

pub enum VerificationQuery<'a> {
    Id(&'a str),
    Identifier(&'a str),
}

// -------------------- Store --------------------

#[async_trait]
pub trait AuthDatabase: Send + Sync {
    // ----- Users
    async fn create_user(&self, user: User) -> StoreResult<User>;
    async fn find_user(&self, query: UserQuery<'_>) -> StoreResult<Option<User>>;
    async fn update_user(&self, user: User) -> StoreResult<Option<User>>;
    async fn delete_user(&self, query: UserQuery<'_>) -> StoreResult<bool>;

    // ----- Sessions
    async fn create_session(&self, session: Session, remember_me: bool) -> StoreResult<Session>;
    async fn find_session(&self, query: SessionQuery<'_>) -> StoreResult<Option<Session>>;
    async fn find_sessions(&self, query: SessionQuery<'_>) -> StoreResult<Vec<Session>>;
    async fn update_session(&self, session: Session) -> StoreResult<Option<Session>>;
    async fn delete_session(&self, query: SessionQuery<'_>) -> StoreResult<bool>;

    // ----- Accounts
    async fn create_account(&self, account: Account) -> StoreResult<Account>;
    async fn find_account(&self, query: AccountQuery<'_>) -> StoreResult<Option<Account>>;
    async fn find_accounts(&self, query: AccountQuery<'_>) -> StoreResult<Vec<Account>>;
    async fn update_account(&self, account: Account) -> StoreResult<Option<Account>>;
    async fn delete_account(&self, query: AccountQuery<'_>) -> StoreResult<bool>;

    // ----- Verifications
    async fn create_verification(&self, verification: Verification) -> StoreResult<Verification>;
    async fn find_verification(
        &self,
        query: VerificationQuery<'_>,
    ) -> StoreResult<Option<Verification>>;
    async fn update_verification(
        &self,
        verification: Verification,
    ) -> StoreResult<Option<Verification>>;
    async fn delete_verification(&self, query: VerificationQuery<'_>) -> StoreResult<bool>;
    async fn consume_verification(&self, identifier: &str) -> StoreResult<Option<Verification>>;
}
