use crate::core::error::AuthrError;
use actix_web::{HttpResponse, ResponseError, http::StatusCode};

impl ResponseError for AuthrError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidEmail | Self::InvalidName | Self::InvalidPassword => {
                StatusCode::BAD_REQUEST
            }
            Self::InvalidCredentials | Self::UserNotFound => StatusCode::UNAUTHORIZED,
            Self::UserAlreadyExists => StatusCode::CONFLICT,
            Self::ProviderNotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "error": self.to_string()
        }))
    }
}
