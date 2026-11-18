diesel::table! {
    account (id) {
        #[max_length = 36]
        id -> Varchar,
        #[max_length = 36]
        userId -> Varchar,
        #[max_length = 255]
        accountId -> Varchar,
        #[max_length = 255]
        providerId -> Varchar,
        accessToken -> Nullable<Text>,
        refreshToken -> Nullable<Text>,
        accessTokenExpiresAt -> Nullable<Timestamp>,
        refreshTokenExpiresAt -> Nullable<Timestamp>,
        scope -> Nullable<Text>,
        idToken -> Nullable<Text>,
        passwordHash -> Nullable<Text>,
        createdAt -> Timestamp,
        updatedAt -> Timestamp,
    }
}

diesel::table! {
    session (id) {
        #[max_length = 36]
        id -> Varchar,
        #[max_length = 36]
        userId -> Varchar,
        #[max_length = 255]
        tokenHash -> Varchar,
        expiresAt -> Timestamp,
        ipAddress -> Nullable<Text>,
        userAgent -> Nullable<Text>,
        createdAt -> Timestamp,
        updatedAt -> Timestamp,
    }
}

diesel::table! {
    user (id) {
        #[max_length = 36]
        id -> Varchar,
        #[max_length = 255]
        name -> Varchar,
        #[max_length = 255]
        email -> Varchar,
        emailVerified -> Bool,
        image -> Nullable<Text>,
        createdAt -> Timestamp,
        updatedAt -> Timestamp,
    }
}

diesel::table! {
    verification (id) {
        #[max_length = 36]
        id -> Varchar,
        #[max_length = 255]
        identifier -> Varchar,
        value -> Text,
        expiresAt -> Timestamp,
        createdAt -> Timestamp,
        updatedAt -> Timestamp,
    }
}

diesel::joinable!(account -> user (userId));
diesel::joinable!(session -> user (userId));

diesel::allow_tables_to_appear_in_same_query!(account, session, user, verification,);
