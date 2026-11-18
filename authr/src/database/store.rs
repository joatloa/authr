use async_trait::async_trait;

use crate::core::types::{Account, Session, User};

pub type StoreResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub trait AuthDatabase:
    UsersStore + SessionsStore + AccountsStore + VerificationStore + Send + Sync
{
}

#[async_trait]
pub trait UsersStore: Send + Sync {
    async fn create_user(&self, user: User) -> StoreResult<User>;
    async fn find_user_by_email(&self, email: &str) -> StoreResult<Option<User>>;
}

#[async_trait]
pub trait SessionsStore: Send + Sync {
    async fn create_session(&self, user_id: &str, remember_me: bool) -> StoreResult<Session>;
}

#[async_trait]
pub trait AccountsStore: Send + Sync {
    async fn link_account(&self, account: Account) -> StoreResult<()>;
}

#[async_trait]
pub trait VerificationStore: Send + Sync {}
