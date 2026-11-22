use std::sync::Arc;

use chrono::Duration;

use crate::{
    core::{
        secrets::AuthrSecrets,
        types::{Account, Session, User, Verification},
    },
    database::store::{
        AccountFilter, AuthDatabase, SessionFilter, StoreResult, UserFilter, VerificationFilter,
    },
};

/// Convenience facade over [`AuthDatabase`] with operation-specific methods.
pub struct AuthrStore<D: AuthDatabase> {
    database: D,
    secrets: Arc<AuthrSecrets>,
}

impl<D: AuthDatabase> AuthrStore<D> {
    /// Wraps a persistence implementation.
    pub fn new(database: D, secrets: Arc<AuthrSecrets>) -> Self {
        Self { database, secrets }
    }

    // -------------------- Users --------------------
    pub async fn create_user(&self, user: User) -> StoreResult<User> {
        self.database.create_user(user).await
    }
    pub async fn find_user_by_id(&self, user_id: &str) -> StoreResult<Option<User>> {
        self.database.find_user(UserFilter::Id(user_id)).await
    }
    pub async fn find_user_by_email(&self, email: &str) -> StoreResult<Option<User>> {
        self.database.find_user(UserFilter::Email(email)).await
    }
    pub async fn update_user(&self, user: User) -> StoreResult<Option<User>> {
        self.database.update_user(user).await
    }
    pub async fn delete_user_by_id(&self, user_id: &str) -> StoreResult<bool> {
        self.database.delete_user(UserFilter::Id(user_id)).await
    }
    pub async fn delete_user_by_email(&self, email: &str) -> StoreResult<bool> {
        self.database.delete_user(UserFilter::Email(email)).await
    }

    // -------------------- Sessions --------------------
    pub async fn create_session(
        &self,
        session: Session,
        remember_me: bool,
    ) -> StoreResult<Session> {
        let lifetime = if remember_me {
            Duration::days(30)
        } else {
            Duration::days(1)
        };

        let mut stored_session = session;
        let raw_token = stored_session.token.clone();

        stored_session.token = self.secrets.hash_session_token(&raw_token);

        let mut session = self
            .database
            .create_session(stored_session, lifetime)
            .await?;

        // Return the original token to the caller.
        session.token = raw_token;

        Ok(session)
    }
    pub async fn find_session_by_token(&self, raw_token: &str) -> StoreResult<Option<Session>> {
        self.database
            .find_session(SessionFilter::Token(
                &self.secrets.hash_session_token(&raw_token),
            ))
            .await
    }
    pub async fn find_sessions_by_user_id(&self, user_id: &str) -> StoreResult<Vec<Session>> {
        self.database
            .find_sessions(SessionFilter::UserId(user_id))
            .await
    }
    pub async fn find_other_sessions(
        &self,
        user_id: &str,
        session_id: &str,
    ) -> StoreResult<Vec<Session>> {
        self.database
            .find_sessions(SessionFilter::UserIdExcept {
                user_id,
                session_id,
            })
            .await
    }
    pub async fn update_session(&self, session: Session) -> StoreResult<Option<Session>> {
        self.database.update_session(session).await
    }
    pub async fn delete_session_by_token(&self, raw_token: &str) -> StoreResult<bool> {
        self.database
            .delete_session(SessionFilter::Token(
                &self.secrets.hash_session_token(&raw_token),
            ))
            .await
    }
    pub async fn delete_user_sessions(&self, user_id: &str) -> StoreResult<bool> {
        self.database
            .delete_session(SessionFilter::UserId(user_id))
            .await
    }
    pub async fn delete_other_sessions(
        &self,
        user_id: &str,
        session_id: &str,
    ) -> StoreResult<bool> {
        self.database
            .delete_session(SessionFilter::UserIdExcept {
                user_id,
                session_id,
            })
            .await
    }

    // -------------------- Accounts --------------------
    pub async fn create_account(&self, account: Account) -> StoreResult<Account> {
        self.database.create_account(account).await
    }
    pub async fn find_account_by_id(&self, account_id: &str) -> StoreResult<Option<Account>> {
        self.database
            .find_account(AccountFilter::Id(account_id))
            .await
    }
    pub async fn find_account_by_provider(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> StoreResult<Option<Account>> {
        self.database
            .find_account(AccountFilter::Provider {
                provider_id,
                account_id,
            })
            .await
    }
    pub async fn find_account_by_user_id(&self, user_id: &str) -> StoreResult<Option<Account>> {
        self.database
            .find_account(AccountFilter::UserId(user_id))
            .await
    }
    pub async fn find_accounts_by_user_id(&self, user_id: &str) -> StoreResult<Vec<Account>> {
        self.database
            .find_accounts(AccountFilter::UserId(user_id))
            .await
    }
    pub async fn update_account(&self, account: Account) -> StoreResult<Option<Account>> {
        self.database.update_account(account).await
    }
    pub async fn delete_account_by_id(&self, account_id: &str) -> StoreResult<bool> {
        self.database
            .delete_account(AccountFilter::Id(account_id))
            .await
    }
    pub async fn delete_accounts_by_user_id(&self, user_id: &str) -> StoreResult<bool> {
        self.database
            .delete_account(AccountFilter::UserId(user_id))
            .await
    }

    // -------------------- Verifications --------------------
    pub async fn create_verification(
        &self,
        verification: Verification,
    ) -> StoreResult<Verification> {
        self.database.create_verification(verification).await
    }
    pub async fn find_verification_by_id(
        &self,
        verification_id: &str,
    ) -> StoreResult<Option<Verification>> {
        self.database
            .find_verification(VerificationFilter::Id(verification_id))
            .await
    }
    pub async fn find_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> StoreResult<Option<Verification>> {
        self.database
            .find_verification(VerificationFilter::Identifier(identifier))
            .await
    }
    pub async fn update_verification(
        &self,
        verification: Verification,
    ) -> StoreResult<Option<Verification>> {
        self.database.update_verification(verification).await
    }
    pub async fn delete_verification_by_id(&self, verification_id: &str) -> StoreResult<bool> {
        self.database
            .delete_verification(VerificationFilter::Id(verification_id))
            .await
    }
    pub async fn delete_verification_by_identifier(&self, identifier: &str) -> StoreResult<bool> {
        self.database
            .delete_verification(VerificationFilter::Identifier(identifier))
            .await
    }
    pub async fn consume_verification(
        &self,
        identifier: &str,
    ) -> StoreResult<Option<Verification>> {
        self.database.consume_verification(identifier).await
    }
}
