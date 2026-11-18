use async_trait::async_trait;

use crate::core::{
    error::AuthrError,
    types::{Account, Session, User, Verification},
};

pub type StoreResult<T> = Result<T, AuthrError>;

// ---- Store Traits
#[async_trait]
pub trait UsersStore: Send + Sync {
    async fn create_user(&self, user: User) -> StoreResult<User>;
    async fn find_user_by_email(&self, email: &str) -> StoreResult<Option<User>>;
}
#[async_trait]
pub trait SessionsStore: Send + Sync {
    async fn create_session(&self, user_id: &str, remember_me: bool) -> StoreResult<Session>;
    async fn delete_session(&self, token: &str) -> StoreResult<()>;
}
#[async_trait]
pub trait AccountsStore: Send + Sync {
    async fn link_account(&self, account: Account) -> StoreResult<()>;
    async fn find_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> StoreResult<Option<Account>>;
}
#[async_trait]
pub trait VerificationStore: Send + Sync {
    async fn create_verification(&self, verification: Verification) -> StoreResult<()>;
}
