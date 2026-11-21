use crate::{
    core::types::{Account, Session, User, Verification},
    database::store::{
        AccountQuery, AuthDatabase, SessionQuery, StoreResult, UserQuery, VerificationQuery,
    },
};

pub struct AuthrStore<D: AuthDatabase> {
    database: D,
}

impl<D: AuthDatabase> AuthrStore<D> {
    pub fn new(database: D) -> Self {
        Self { database }
    }

    // -------------------- Users --------------------
    pub async fn create_user(&self, user: User) -> StoreResult<User> {
        self.database.create_user(user).await
    }
    pub async fn find_user_by_id(&self, user_id: &str) -> StoreResult<Option<User>> {
        self.database.find_user(UserQuery::Id(user_id)).await
    }
    pub async fn find_user_by_email(&self, email: &str) -> StoreResult<Option<User>> {
        self.database.find_user(UserQuery::Email(email)).await
    }
    pub async fn update_user(&self, user: User) -> StoreResult<Option<User>> {
        self.database.update_user(user).await
    }
    pub async fn delete_user_by_id(&self, user_id: &str) -> StoreResult<bool> {
        self.database.delete_user(UserQuery::Id(user_id)).await
    }
    pub async fn delete_user_by_email(&self, email: &str) -> StoreResult<bool> {
        self.database.delete_user(UserQuery::Email(email)).await
    }

    // -------------------- Sessions --------------------
    pub async fn create_session(
        &self,
        session: Session,
        remember_me: bool,
    ) -> StoreResult<Session> {
        self.database.create_session(session, remember_me).await
    }
    pub async fn find_session_by_token(&self, token: &str) -> StoreResult<Option<Session>> {
        self.database.find_session(SessionQuery::Token(token)).await
    }
    pub async fn find_sessions_by_user_id(&self, user_id: &str) -> StoreResult<Vec<Session>> {
        self.database
            .find_sessions(SessionQuery::UserId(user_id))
            .await
    }
    pub async fn find_other_sessions(
        &self,
        user_id: &str,
        session_id: &str,
    ) -> StoreResult<Vec<Session>> {
        self.database
            .find_sessions(SessionQuery::UserIdExcept {
                user_id,
                session_id,
            })
            .await
    }
    pub async fn update_session(&self, session: Session) -> StoreResult<Option<Session>> {
        self.database.update_session(session).await
    }
    pub async fn delete_session_by_token(&self, token: &str) -> StoreResult<bool> {
        self.database
            .delete_session(SessionQuery::Token(token))
            .await
    }
    pub async fn delete_user_sessions(&self, user_id: &str) -> StoreResult<bool> {
        self.database
            .delete_session(SessionQuery::UserId(user_id))
            .await
    }
    pub async fn delete_other_sessions(
        &self,
        user_id: &str,
        session_id: &str,
    ) -> StoreResult<bool> {
        self.database
            .delete_session(SessionQuery::UserIdExcept {
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
            .find_account(AccountQuery::Id(account_id))
            .await
    }
    pub async fn find_account_by_provider(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> StoreResult<Option<Account>> {
        self.database
            .find_account(AccountQuery::Provider {
                provider_id,
                account_id,
            })
            .await
    }
    pub async fn find_account_by_user_id(&self, user_id: &str) -> StoreResult<Option<Account>> {
        self.database
            .find_account(AccountQuery::UserId(user_id))
            .await
    }
    pub async fn find_accounts_by_user_id(&self, user_id: &str) -> StoreResult<Vec<Account>> {
        self.database
            .find_accounts(AccountQuery::UserId(user_id))
            .await
    }
    pub async fn update_account(&self, account: Account) -> StoreResult<Option<Account>> {
        self.database.update_account(account).await
    }
    pub async fn delete_account_by_id(&self, account_id: &str) -> StoreResult<bool> {
        self.database
            .delete_account(AccountQuery::Id(account_id))
            .await
    }
    pub async fn delete_accounts_by_user_id(&self, user_id: &str) -> StoreResult<bool> {
        self.database
            .delete_account(AccountQuery::UserId(user_id))
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
            .find_verification(VerificationQuery::Id(verification_id))
            .await
    }
    pub async fn find_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> StoreResult<Option<Verification>> {
        self.database
            .find_verification(VerificationQuery::Identifier(identifier))
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
            .delete_verification(VerificationQuery::Id(verification_id))
            .await
    }
    pub async fn delete_verification_by_identifier(&self, identifier: &str) -> StoreResult<bool> {
        self.database
            .delete_verification(VerificationQuery::Identifier(identifier))
            .await
    }
    pub async fn consume_verification(
        &self,
        identifier: &str,
    ) -> StoreResult<Option<Verification>> {
        self.database.consume_verification(identifier).await
    }
}
