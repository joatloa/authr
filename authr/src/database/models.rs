#![allow(non_snake_case)]

use chrono::NaiveDateTime;
use diesel::{Selectable, deserialize::Queryable, prelude::Insertable};
use uuid::Uuid;

use crate::{
    core::types::{Account, Session, User, Verification},
    database::schema::{account, session, user, verification},
};

// ----- Queryables rows

#[derive(Queryable, Selectable)]
#[diesel(table_name = user)]
pub struct UserRow {
    pub id: String,
    pub name: String,
    pub email: String,
    pub emailVerified: bool,
    pub image: Option<String>,
    pub createdAt: NaiveDateTime,
    pub updatedAt: NaiveDateTime,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        Self {
            id: Uuid::parse_str(&row.id).expect("Invalid user UUID in database"),
            name: row.name,
            email: row.email,
            email_verified: row.emailVerified,
            image: row.image,
            created_at: row.createdAt.and_utc(),
            updated_at: row.updatedAt.and_utc(),
        }
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = session)]
pub struct SessionRow {
    pub id: String,
    pub userId: String,
    pub tokenHash: String,
    pub expiresAt: NaiveDateTime,
    pub ipAddress: Option<String>,
    pub userAgent: Option<String>,
    pub createdAt: NaiveDateTime,
    pub updatedAt: NaiveDateTime,
}

impl From<SessionRow> for Session {
    fn from(row: SessionRow) -> Self {
        Self {
            id: Uuid::parse_str(&row.id).expect("Invalid user UUID in database"),
            user_id: Uuid::parse_str(&row.userId).expect("Invalid user UUID in database"),
            token: row.tokenHash,
            expires_at: row.expiresAt.and_utc(),
            ip_address: row.ipAddress,
            user_agent: row.userAgent,
            created_at: row.createdAt.and_utc(),
            updated_at: row.updatedAt.and_utc(),
        }
    }
}

impl SessionRow {
    pub fn into_session(self, token: String) -> Session {
        Session {
            id: Uuid::parse_str(&self.id).expect("Invalid session UUID in database"),
            user_id: Uuid::parse_str(&self.userId).expect("Invalid user UUID in database"),
            token,
            expires_at: self.expiresAt.and_utc(),
            ip_address: self.ipAddress,
            user_agent: self.userAgent,
            created_at: self.createdAt.and_utc(),
            updated_at: self.updatedAt.and_utc(),
        }
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = account)]
pub struct AccountRow {
    pub id: String,
    pub userId: String,
    pub accountId: String,
    pub providerId: String,
    pub accessToken: Option<String>,
    pub refreshToken: Option<String>,
    pub accessTokenExpiresAt: Option<NaiveDateTime>,
    pub refreshTokenExpiresAt: Option<NaiveDateTime>,
    pub scope: Option<String>,
    pub idToken: Option<String>,
    pub passwordHash: Option<String>,
    pub createdAt: NaiveDateTime,
    pub updatedAt: NaiveDateTime,
}

impl From<AccountRow> for Account {
    fn from(row: AccountRow) -> Self {
        Self {
            id: Uuid::parse_str(&row.id).expect("Invalid account UUID in database"),
            user_id: Uuid::parse_str(&row.userId).expect("Invalid user UUID in database"),
            account_id: row.accountId,
            provider_id: row.providerId,
            access_token: row.accessToken,
            refresh_token: row.refreshToken,
            access_token_expires_at: row.accessTokenExpiresAt.map(|t| t.and_utc()),
            refresh_token_expires_at: row.refreshTokenExpiresAt.map(|t| t.and_utc()),
            scope: row.scope,
            id_token: row.idToken,
            password_hash: row.passwordHash,
            created_at: row.createdAt.and_utc(),
            updated_at: row.updatedAt.and_utc(),
        }
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = verification)]
pub struct VerificationRow {
    pub id: String,
    pub identifier: String,
    pub value: String,
    pub expiresAt: NaiveDateTime,
    pub createdAt: NaiveDateTime,
    pub updatedAt: NaiveDateTime,
}

impl From<VerificationRow> for Verification {
    fn from(row: VerificationRow) -> Self {
        Self {
            id: Uuid::parse_str(&row.id).expect("Invalid verification UUID in database"),
            identifier: row.identifier,
            value: row.value,
            expires_at: row.expiresAt.and_utc(),
            created_at: row.createdAt.and_utc(),
            updated_at: row.updatedAt.and_utc(),
        }
    }
}

// ----- Insertable rows

#[derive(Insertable)]
#[diesel(table_name = user)]
#[diesel(treat_none_as_default_value = false)]
pub struct NewUser<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub email: &'a str,
    pub emailVerified: bool,
    pub image: Option<&'a str>,
    pub createdAt: NaiveDateTime,
    pub updatedAt: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = account)]
#[diesel(treat_none_as_default_value = false)]
pub struct NewAccount<'a> {
    pub id: &'a str,
    pub userId: &'a str,
    pub accountId: &'a str,
    pub providerId: &'a str,
    pub accessToken: Option<&'a str>,
    pub refreshToken: Option<&'a str>,
    pub accessTokenExpiresAt: Option<NaiveDateTime>,
    pub refreshTokenExpiresAt: Option<NaiveDateTime>,
    pub scope: Option<&'a str>,
    pub idToken: Option<&'a str>,
    pub passwordHash: Option<&'a str>,
    pub createdAt: NaiveDateTime,
    pub updatedAt: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = session)]
#[diesel(treat_none_as_default_value = false)]
pub struct NewSession<'a> {
    pub id: &'a str,
    pub userId: &'a str,
    pub tokenHash: &'a str,
    pub expiresAt: NaiveDateTime,
    pub ipAddress: Option<&'a str>,
    pub userAgent: Option<&'a str>,
    pub createdAt: NaiveDateTime,
    pub updatedAt: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = verification)]
#[diesel(treat_none_as_default_value = false)]
pub struct NewVerification<'a> {
    pub id: &'a str,
    pub identifier: &'a str,
    pub value: &'a str,
    pub expiresAt: NaiveDateTime,
    pub createdAt: NaiveDateTime,
    pub updatedAt: NaiveDateTime,
}
