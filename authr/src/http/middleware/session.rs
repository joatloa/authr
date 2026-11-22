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
    http::cookie::extract_session_token,
};

// -------------------- Session Middleware --------------------

#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub session: Session,
    pub user: User,
    pub token: String,
}

pub async fn require_session<D, B>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, Error>
where
    D: AuthDatabase + 'static,
    B: MessageBody + 'static,
{
    // ----- Retrieve ctx
    let Some(ctx) = req.app_data::<web::Data<AuthrContext<D>>>().cloned() else {
        tracing::error!("AuthrContext is missing from application data");

        return Ok(req
            .into_response(HttpResponse::InternalServerError().finish())
            .map_into_right_body());
    };

    // ----- Extract session token
    let Some(session_token) = extract_session_token(req.request()) else {
        return Ok(req
            .into_response(HttpResponse::Unauthorized().json(serde_json::json!({
                "message": "Unauthorized"
            })))
            .map_into_right_body());
    };

    // ----- Resolve session
    let authenticated = match resolve_session(&ctx, &session_token).await {
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

// -------------------- Helpers --------------------

pub async fn resolve_session<D: AuthDatabase + 'static>(
    ctx: &AuthrContext<D>,
    session_token: &str,
) -> Result<Option<AuthenticatedSession>, AuthrError> {
    // ----- Find session
    let Some(session) = ctx.store().find_session_by_token(session_token).await? else {
        return Ok(None);
    };

    // ----- Check expiration
    if session.expires_at <= Utc::now() {
        ctx.store().delete_session_by_token(session_token).await?;

        return Ok(None);
    }

    // ----- Find user
    let user_id = session.user_id.to_string();

    let Some(user) = ctx.store().find_user_by_id(&user_id).await? else {
        ctx.store().delete_session_by_token(session_token).await?;

        return Ok(None);
    };

    Ok(Some(AuthenticatedSession {
        session,
        user,
        token: session_token.to_string(),
    }))
}
