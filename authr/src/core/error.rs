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
    #[error("Invalid password reset token")]
    InvalidResetToken,
    #[error("Invalid callback URL")]
    InvalidCallbackUrl,
    #[error("Password reset is not enabled")]
    PasswordResetDisabled,
    #[error("Failed to deliver password reset email")]
    PasswordResetDeliveryFailed,

    // -------------------- Authentication --------------------
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,

    // -------------------- Database --------------------

    // Users
    #[error("Failed to create user")]
    UserCreationFailed,
    #[error("Failed to find user")]
    UserLookupFailed,
    #[error("Failed to update user")]
    UserUpdateFailed,
    #[error("Failed to delete user")]
    UserDeletionFailed,

    // Accounts
    #[error("Failed to create account")]
    AccountCreationFailed,
    #[error("Failed to find account")]
    AccountLookupFailed,
    #[error("Failed to update account")]
    AccountUpdateFailed,
    #[error("Failed to delete account")]
    AccountDeletionFailed,

    // Sessions
    #[error("Failed to create session")]
    SessionCreationFailed,
    #[error("Failed to find session")]
    SessionLookupFailed,
    #[error("Failed to update session")]
    SessionUpdateFailed,
    #[error("Failed to delete session")]
    SessionDeletionFailed,

    // Verification
    #[error("Failed to create verification")]
    VerificationCreationFailed,
    #[error("Failed to find verification")]
    VerificationLookupFailed,
    #[error("Failed to update verification")]
    VerificationUpdateFailed,
    #[error("Failed to delete verification")]
    VerificationDeletionFailed,
    #[error("Failed to consume verification")]
    VerificationConsumptionFailed,

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

    // -------------------- General --------------------
    #[error("Internal error")]
    Internal,
}
