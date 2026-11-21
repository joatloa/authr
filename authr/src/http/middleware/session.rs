use actix_web::{
    HttpMessage, HttpResponse,
    body::{EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    error::Error,
    middleware::Next,
    web,
};
use chrono::Utc;

use crate::{
    core::{
        auth::AuthrContext,
        error::AuthrError,
        types::{Session, User},
    },
    database::store::AuthDatabase,
    http::utils::SESSION_COOKIE_NAME,
};

// ----- Authenticated Session
#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub session: Session,
    pub user: User,
    pub token: String,
}

// ----- Session Resolution
pub async fn resolve_session<D: AuthDatabase + 'static>(
    token: &str,
    ctx: &AuthrContext<D>,
) -> Result<Option<AuthenticatedSession>, AuthrError> {
    // ----- Find session
    let Some(session) = ctx.store().find_session_by_token(token).await? else {
        return Ok(None);
    };

    // ----- Check expiration
    if session.expires_at <= Utc::now() {
        ctx.store().delete_session_by_token(token).await?;

        return Ok(None);
    }

    // ----- Find user
    let user_id = session.user_id.to_string();

    let Some(user) = ctx.store().find_user_by_id(&user_id).await? else {
        return Ok(None);
    };

    Ok(Some(AuthenticatedSession {
        session,
        user,
        token: token.to_string(),
    }))
}

// ----- Authentication Middleware
pub async fn require_session<D, B>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, Error>
where
    D: AuthDatabase + 'static,
    B: MessageBody + 'static,
{
    // ----- Retrieve auth data
    let Some(data) = req.app_data::<web::Data<AuthrContext<D>>>().cloned() else {
        tracing::error!("AuthrContext is missing from application data");

        return Ok(req
            .into_response(HttpResponse::InternalServerError().finish())
            .map_into_right_body());
    };

    // ----- Extract session token
    let Some(token) = req
        .cookie(SESSION_COOKIE_NAME)
        .map(|cookie| cookie.value().to_string())
    else {
        return Ok(req
            .into_response(HttpResponse::Unauthorized().json(serde_json::json!({
                "message": "Unauthorized"
            })))
            .map_into_right_body());
    };

    // ----- Resolve session
    let authenticated = match resolve_session(&token, &data).await {
        Ok(Some(authenticated)) => authenticated,
        Ok(None) => {
            return Ok(req
                .into_response(HttpResponse::Unauthorized().json(serde_json::json!({
                    "message": "Unauthorized"
                })))
                .map_into_right_body());
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "Failed to resolve authenticated session"
            );

            return Ok(req
                .into_response(HttpResponse::InternalServerError().finish())
                .map_into_right_body());
        }
    };

    tracing::debug!(
        session_id = %authenticated.session.id,
        user_id = %authenticated.user.id,
        "Authenticated request"
    );

    // ----- Store authenticated context
    req.extensions_mut().insert(authenticated);

    next.call(req)
        .await
        .map(ServiceResponse::map_into_left_body)
}
