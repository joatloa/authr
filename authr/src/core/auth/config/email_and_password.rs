use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;

use crate::core::{error::AuthrError, types::User};

#[async_trait]
pub trait PasswordResetSender: Send + Sync + Debug {
    async fn send_reset_password(
        &self,
        user: User,
        url: String,
        token: String,
    ) -> Result<(), AuthrError>;
}

#[derive(Debug, Clone)]
/// Password authentication policy.
pub struct EmailAndPassword {
    /// Maximum number of characters allowed in a password.
    ///
    /// Defaults to `128`.
    pub max_password_length: usize,
    /// Minimum number of characters required in a password.
    ///
    /// Defaults to `8`.
    pub min_password_length: usize,
    /// Whether Authr should automatically create a session and sign in
    /// the user after a successful registration.
    ///
    /// Defaults to `true`.
    pub auto_sign_in: bool,
    /// Optional application callback used to deliver password reset links.
    pub reset_password_sender: Option<Arc<dyn PasswordResetSender>>,
}

impl Default for EmailAndPassword {
    fn default() -> Self {
        Self {
            max_password_length: 128,
            min_password_length: 8,
            auto_sign_in: true,
            reset_password_sender: None,
        }
    }
}
