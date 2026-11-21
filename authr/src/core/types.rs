use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::utils::generate_random_token;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl User {
    pub fn new(name: String, email: String, email_verified: bool, image: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            email,
            email_verified,
            image,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: Uuid,
    pub user_id: Uuid,
    pub account_id: String,
    pub provider_id: String,

    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub id_token: Option<String>,

    pub password_hash: Option<String>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl Account {
    pub fn new_credential(user_id: Uuid, password_hash: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            account_id: user_id.to_string(),
            provider_id: "credential".to_string(),
            password_hash: Some(password_hash),
            ..Default::default()
        }
    }
    pub fn new_social(
        user_id: Uuid,
        provider_id: String,
        account_id: String,
        access_token: Option<String>,
        refresh_token: Option<String>,
        access_token_expires_at: Option<DateTime<Utc>>,
        refresh_token_expires_at: Option<DateTime<Utc>>,
        scope: Option<String>,
        id_token: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            provider_id,
            account_id,
            access_token,
            refresh_token,
            access_token_expires_at,
            refresh_token_expires_at,
            scope,
            id_token,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    pub id: Uuid,
    pub identifier: String,
    pub value: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl Verification {
    pub fn new(identifier: String, value: String) -> Self {
        Verification {
            id: Uuid::new_v4(),
            identifier,
            value,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl Session {
    pub fn new(user_id: Uuid, ip_address: Option<String>, user_agent: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            token: generate_random_token(),
            ip_address,
            user_agent,
            ..Default::default()
        }
    }
}
