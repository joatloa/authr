use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthrError {
    // -------------------- Validation --------------------
    #[error("Invalid email")]
    InvalidEmail,
    #[error("Invalid name")]
    InvalidName,
    #[error("Invalid password")]
    InvalidPassword,

    // -------------------- Authentication --------------------
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("User already exists")]
    UserAlreadyExists,

    // -------------------- Database --------------------
    #[error("Failed to find user")]
    UserLookupFailed,
    #[error("Failed to create user")]
    UserCreationFailed,
    #[error("Failed to create account")]
    AccountCreationFailed,
    #[error("Failed to find account")]
    AccountLookupFailed,
    #[error("Failed to create session")]
    SessionCreationFailed,
    #[error("Failed to delete session")]
    SessionDeletionFailed,
    #[error("Failed to create verification")]
    VerificationCreationFailed,

    // -------------------- Cryptography --------------------
    #[error("Password hashing failed")]
    PasswordHashingFailed,
    #[error("Password verification failed")]
    PasswordVerificationFailed,

    // -------------------- OAuth --------------------
    #[error("OAuth provider not found")]
    ProviderNotFound,
    #[error("OAuth authorization failed")]
    OAuthAuthorizationFailed,
    #[error("OAuth token exchange failed")]
    OAuthTokenExchangeFailed,
    #[error("OAuth user information retrieval failed")]
    OAuthUserInfoFailed,
    #[error("Invalid OAuth state")]
    InvalidOAuthState,
    #[error("OAuth transaction expired")]
    OAuthTransactionExpired,

    // -------------------- General --------------------
    #[error("Internal error")]
    Internal,
}
