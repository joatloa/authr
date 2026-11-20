use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use tokio::sync::Mutex;

use authr::{
    core::{
        types::{Account, Session, User, Verification},
        utils::hash_str,
    },
    database::store::{
        AccountQuery, AuthDatabase, SessionQuery, StoreResult, UserQuery, VerificationQuery,
    },
};

#[derive(Default)]
struct TestDatabaseState {
    users: Vec<User>,
    sessions: Vec<Session>,
    accounts: Vec<Account>,
    verifications: Vec<Verification>,
}

#[derive(Clone, Default)]
pub struct TestDatabase {
    state: Arc<Mutex<TestDatabaseState>>,
}

#[async_trait]
impl AuthDatabase for TestDatabase {
    // ----- Users
    async fn create_user(&self, mut user: User) -> StoreResult<User> {
        let mut state = self.state.lock().await;

        let now = Utc::now();
        user.created_at = now;
        user.updated_at = now;

        state.users.push(user.clone());

        Ok(user)
    }
    async fn find_user(&self, query: UserQuery<'_>) -> StoreResult<Option<User>> {
        let state = self.state.lock().await;

        let user = state.users.iter().find(|user| match query {
            UserQuery::Id(id) => user.id.to_string() == id,
            UserQuery::Email(email) => user.email == email,
        });

        Ok(user.cloned())
    }
    async fn update_user(&self, mut user: User) -> StoreResult<Option<User>> {
        let mut state = self.state.lock().await;

        let Some(existing) = state
            .users
            .iter_mut()
            .find(|existing| existing.id == user.id)
        else {
            return Ok(None);
        };

        user.created_at = existing.created_at;
        user.updated_at = Utc::now();

        *existing = user.clone();

        Ok(Some(user))
    }
    async fn delete_user(&self, query: UserQuery<'_>) -> StoreResult<bool> {
        let mut state = self.state.lock().await;

        let previous_len = state.users.len();

        state.users.retain(|user| !match query {
            UserQuery::Id(id) => user.id.to_string() == id,
            UserQuery::Email(email) => user.email == email,
        });

        Ok(state.users.len() < previous_len)
    }

    // ----- Sessions
    async fn create_session(
        &self,
        mut session: Session,
        remember_me: bool,
    ) -> StoreResult<Session> {
        let mut state = self.state.lock().await;

        let now = Utc::now();
        let duration = if remember_me {
            Duration::days(30)
        } else {
            Duration::days(1)
        };

        session.created_at = now;
        session.updated_at = now;
        session.expires_at = now + duration;

        let mut stored_session = session.clone();
        stored_session.token = hash_str(&session.token);

        state.sessions.push(stored_session);

        Ok(session)
    }
    async fn find_session(&self, query: SessionQuery<'_>) -> StoreResult<Option<Session>> {
        let state = self.state.lock().await;

        let session = state.sessions.iter().find(|session| match query {
            SessionQuery::Token(token) => session.token == hash_str(token),
            SessionQuery::UserId(user_id) => session.user_id.to_string() == user_id,
        });

        Ok(session.cloned().map(|mut session| {
            session.token.clear();
            session
        }))
    }
    async fn update_session(&self, mut session: Session) -> StoreResult<Option<Session>> {
        let mut state = self.state.lock().await;

        let Some(existing) = state
            .sessions
            .iter_mut()
            .find(|existing| existing.id == session.id)
        else {
            return Ok(None);
        };

        session.created_at = existing.created_at;
        session.updated_at = Utc::now();

        existing.expires_at = session.expires_at;
        existing.ip_address = session.ip_address.clone();
        existing.user_agent = session.user_agent.clone();
        existing.updated_at = session.updated_at;

        Ok(Some(session))
    }
    async fn delete_session(&self, query: SessionQuery<'_>) -> StoreResult<bool> {
        let mut state = self.state.lock().await;

        let previous_len = state.sessions.len();

        state.sessions.retain(|session| !match query {
            SessionQuery::Token(token) => session.token == hash_str(token),
            SessionQuery::UserId(user_id) => session.user_id.to_string() == user_id,
        });

        Ok(state.sessions.len() < previous_len)
    }

    // ----- Accounts
    async fn create_account(&self, mut account: Account) -> StoreResult<Account> {
        let mut state = self.state.lock().await;

        account.updated_at = Utc::now();

        state.accounts.push(account.clone());

        Ok(account)
    }
    async fn find_account(&self, query: AccountQuery<'_>) -> StoreResult<Option<Account>> {
        let state = self.state.lock().await;

        let account = state.accounts.iter().find(|account| match query {
            AccountQuery::Id(id) => account.id.to_string() == id,
            AccountQuery::Provider {
                provider_id,
                account_id,
            } => account.provider_id == provider_id && account.account_id == account_id,
            AccountQuery::UserId(user_id) => account.user_id.to_string() == user_id,
        });

        Ok(account.cloned())
    }
    async fn find_accounts(&self, query: AccountQuery<'_>) -> StoreResult<Vec<Account>> {
        let state = self.state.lock().await;

        let accounts = state
            .accounts
            .iter()
            .filter(|account| match query {
                AccountQuery::Id(id) => account.id.to_string() == id,
                AccountQuery::Provider {
                    provider_id,
                    account_id,
                } => account.provider_id == provider_id && account.account_id == account_id,
                AccountQuery::UserId(user_id) => account.user_id.to_string() == user_id,
            })
            .cloned()
            .collect();

        Ok(accounts)
    }
    async fn update_account(&self, mut account: Account) -> StoreResult<Option<Account>> {
        let mut state = self.state.lock().await;

        let Some(existing) = state
            .accounts
            .iter_mut()
            .find(|existing| existing.id == account.id)
        else {
            return Ok(None);
        };

        account.created_at = existing.created_at;
        account.updated_at = Utc::now();

        *existing = account.clone();

        Ok(Some(account))
    }
    async fn delete_account(&self, query: AccountQuery<'_>) -> StoreResult<bool> {
        let mut state = self.state.lock().await;

        let previous_len = state.accounts.len();

        state.accounts.retain(|account| !match query {
            AccountQuery::Id(id) => account.id.to_string() == id,
            AccountQuery::Provider {
                provider_id,
                account_id,
            } => account.provider_id == provider_id && account.account_id == account_id,
            AccountQuery::UserId(user_id) => account.user_id.to_string() == user_id,
        });

        Ok(state.accounts.len() < previous_len)
    }

    // ----- Verifications
    async fn create_verification(
        &self,
        mut verification: Verification,
    ) -> StoreResult<Verification> {
        let mut state = self.state.lock().await;

        let now = Utc::now();
        verification.created_at = now;
        verification.updated_at = now;

        state.verifications.push(verification.clone());

        Ok(verification)
    }
    async fn find_verification(
        &self,
        query: VerificationQuery<'_>,
    ) -> StoreResult<Option<Verification>> {
        let state = self.state.lock().await;

        let verification = state.verifications.iter().find(|verification| match query {
            VerificationQuery::Id(id) => verification.id.to_string() == id,
            VerificationQuery::Identifier(identifier) => verification.identifier == identifier,
        });

        Ok(verification.cloned())
    }
    async fn update_verification(
        &self,
        mut verification: Verification,
    ) -> StoreResult<Option<Verification>> {
        let mut state = self.state.lock().await;

        let Some(existing) = state
            .verifications
            .iter_mut()
            .find(|existing| existing.id == verification.id)
        else {
            return Ok(None);
        };

        verification.created_at = existing.created_at;
        verification.updated_at = Utc::now();

        *existing = verification.clone();

        Ok(Some(verification))
    }
    async fn delete_verification(&self, query: VerificationQuery<'_>) -> StoreResult<bool> {
        let mut state = self.state.lock().await;

        let previous_len = state.verifications.len();

        state.verifications.retain(|verification| !match query {
            VerificationQuery::Id(id) => verification.id.to_string() == id,
            VerificationQuery::Identifier(identifier) => verification.identifier == identifier,
        });

        Ok(state.verifications.len() < previous_len)
    }
    async fn consume_verification(&self, identifier: &str) -> StoreResult<Option<Verification>> {
        let mut state = self.state.lock().await;

        let Some(index) = state
            .verifications
            .iter()
            .position(|verification| verification.identifier == identifier)
        else {
            return Ok(None);
        };

        Ok(Some(state.verifications.remove(index)))
    }
}
