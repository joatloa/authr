use chrono::{Duration, Utc};

use authr::core::{
    oauth::types::OAuthTransaction,
    types::{Account, Session, User, Verification},
};
use uuid::Uuid;

use crate::common::mock::TestDatabase;

pub(crate) async fn seed_user(database: &TestDatabase, name: &str, email: &str) -> User {
    database
        .to_authr_store()
        .create_user(User::new(name.to_string(), email.to_string(), false, None))
        .await
        .expect("test user should be created")
}

pub(crate) async fn seed_session(database: &TestDatabase, user_id: Uuid) -> Session {
    database
        .to_authr_store()
        .create_session(Session::new(user_id, None, None), false)
        .await
        .expect("test session should be created")
}

pub(crate) async fn expire_session(database: &TestDatabase, mut session: Session) -> Session {
    session.expires_at = Utc::now() - Duration::seconds(60);
    database
        .to_authr_store()
        .update_session(session)
        .await
        .expect("session should update")
        .expect("test session should exist")
}

pub(crate) async fn seed_account(database: &TestDatabase, account: Account) -> Account {
    database
        .to_authr_store()
        .create_account(account)
        .await
        .expect("test account should be created")
}

pub(crate) async fn seed_verification(database: &TestDatabase, verification: Verification) {
    database
        .to_authr_store()
        .create_verification(verification)
        .await
        .expect("test verification should be created");
}

pub(crate) async fn seed_oauth_transaction(
    database: &TestDatabase,
    state: &str,
    provider_id: &str,
    callback_url: Option<String>,
) {
    let transaction = OAuthTransaction {
        provider_id: provider_id.into(),
        code_verifier: "mock-code-verifier".into(),
        callback_url,
    };
    seed_verification(
        database,
        Verification::new(
            format!("oauth:{state}"),
            serde_json::to_string(&transaction).expect("OAuth transaction should serialize"),
            Utc::now() + Duration::minutes(10),
        ),
    )
    .await;
}
