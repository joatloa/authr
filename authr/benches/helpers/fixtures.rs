#![allow(unused)]

use authr::core::types::{Account, Session, User, Verification};
use chrono::{Duration, Utc};
use uuid::Uuid;

pub fn user() -> User {
    User::new(
        "Benchmark User".into(),
        format!("{}@benchmark.local", Uuid::new_v4()),
        true,
        None,
    )
}

pub fn account(user_id: Uuid) -> Account {
    Account::new_credential(user_id, "benchmark-password-hash".into())
}

pub fn session(user_id: Uuid) -> Session {
    Session::new(
        user_id,
        Some("127.0.0.1".into()),
        Some("Authr Benchmark".into()),
    )
}

pub fn verification() -> Verification {
    Verification::new(
        format!("benchmark-{}", Uuid::new_v4()),
        "benchmark-verification-value".into(),
        Utc::now() + Duration::minutes(10),
    )
}
