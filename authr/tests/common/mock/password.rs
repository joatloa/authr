use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use authr::core::{auth::PasswordResetSender, error::AuthrError, types::User};

#[derive(Debug, Clone, Default)]
pub struct RecordingPasswordResetSender(Arc<Mutex<Vec<(String, String)>>>);

impl RecordingPasswordResetSender {
    pub fn token(&self) -> String {
        self.0
            .lock()
            .unwrap()
            .last()
            .expect("no reset email has been recorded")
            .1
            .clone()
    }

    pub fn url(&self) -> String {
        self.0
            .lock()
            .unwrap()
            .last()
            .expect("no reset email has been recorded")
            .0
            .clone()
    }
}

#[async_trait]
impl PasswordResetSender for RecordingPasswordResetSender {
    async fn send_reset_password(
        &self,
        _user: User,
        url: String,
        token: String,
    ) -> Result<(), AuthrError> {
        self.0.lock().unwrap().push((url, token));
        Ok(())
    }
}
