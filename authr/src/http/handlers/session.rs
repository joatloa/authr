use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder, web};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::{
    core::auth::AuthrContext,
    database::store::AuthDatabase,
    http::{
        cookie::{build_removal_session_cookie, extract_session_token},
        middleware::session::{AuthenticatedSession, resolve_session},
    },
};

// -------------------- Get Session - GET "/get-session" --------------------

#[tracing::instrument(name = "auth.get_session", skip_all)]
pub async fn get_session<D: AuthDatabase + 'static>(
    req: HttpRequest,
    ctx: web::Data<AuthrContext<D>>,
) -> impl Responder {
    let Some(session_token) = extract_session_token(&req) else {
        return HttpResponse::Ok().json(Option::<serde_json::Value>::None);
    };

    // ----- Resolve session
    match resolve_session(&ctx, &session_token).await {
        Ok(Some(authenticated)) => {
            tracing::debug!(
                session_id = %authenticated.session.id,
                user_id = %authenticated.user.id,
                "Current session retrieved"
            );

            HttpResponse::Ok().json(json!({
                "session": authenticated.session,
                "user": authenticated.user
            }))
        }
        Ok(None) => {
            tracing::debug!("No valid session found");

            HttpResponse::Ok().json(Option::<serde_json::Value>::None)
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "Failed to retrieve current session"
            );

            HttpResponse::InternalServerError().json(json!({
                "message": "Failed to retrieve session"
            }))
        }
    }
}

// -------------------- List Session - GET "/list-sessions" --------------------

#[tracing::instrument(name = "auth.list_sessions", skip_all)]
pub async fn list_sessions<D: AuthDatabase + 'static>(
    req: HttpRequest,
    ctx: web::Data<AuthrContext<D>>,
) -> impl Responder {
    let extensions = req.extensions();
    let Some(authenticated) = extensions.get::<AuthenticatedSession>() else {
        return HttpResponse::Unauthorized().finish();
    };

    // ----- Find user sessions
    let user_id = authenticated.user.id.to_string();

    match ctx.store().find_sessions_by_user_id(&user_id).await {
        Ok(sessions) => {
            let now = Utc::now();

            let sessions: Vec<_> = sessions
                .into_iter()
                .filter(|session| session.expires_at > now)
                .collect();

            tracing::debug!(
                user_id = %authenticated.user.id,
                session_count = sessions.len(),
                "Retrieved active sessions"
            );

            HttpResponse::Ok().json(sessions)
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "Failed to list user sessions"
            );

            HttpResponse::InternalServerError().json(json!({
                "message": "Failed to retrieve sessions"
            }))
        }
    }
}

// -------------------- Revoke Session - POST "/revoke-session" --------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeSessionRequest {
    pub token: String,
}

#[tracing::instrument(
    name = "auth.revoke_session",
    skip_all,
    fields(has_token = !body.token.is_empty())
)]
pub async fn revoke_session<D: AuthDatabase + 'static>(
    req: HttpRequest,
    ctx: web::Data<AuthrContext<D>>,
    body: web::Json<RevokeSessionRequest>,
) -> impl Responder {
    let extensions = req.extensions();
    let Some(authenticated) = extensions.get::<AuthenticatedSession>() else {
        return HttpResponse::Unauthorized().finish();
    };

    let session_token = body.token.trim();

    if session_token.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "message": "Session token is required"
        }));
    }

    // ----- Find target session
    let session = match ctx.store().find_session_by_token(session_token).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({
                "message": "Session not found"
            }));
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "Failed to find session to revoke"
            );

            return HttpResponse::InternalServerError().finish();
        }
    };

    // ----- Verify ownership
    if session.user_id != authenticated.user.id {
        return HttpResponse::Forbidden().json(json!({
            "message": "Cannot revoke another user's session"
        }));
    }

    // ----- Revoke session
    match ctx.store().delete_session_by_token(session_token).await {
        Ok(_) => {
            tracing::info!(
                session_id = %session.id,
                user_id = %authenticated.user.id,
                "Session revoked"
            );

            let mut response = HttpResponse::Ok();

            if session_token == authenticated.token {
                response.cookie(build_removal_session_cookie());
            }

            response.json(json!({
                "success": true
            }))
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "Failed to revoke session"
            );

            HttpResponse::InternalServerError().finish()
        }
    }
}

// -------------------- Revoke All Sessions - POST "/revoke-sessions" --------------------

#[tracing::instrument(name = "auth.revoke_sessions", skip_all)]
pub async fn revoke_sessions<D: AuthDatabase + 'static>(
    req: HttpRequest,
    ctx: web::Data<AuthrContext<D>>,
) -> impl Responder {
    let extensions = req.extensions();
    let Some(authenticated) = extensions.get::<AuthenticatedSession>() else {
        return HttpResponse::Unauthorized().finish();
    };

    // ----- Revoke user sessions
    let user_id = authenticated.user.id.to_string();

    match ctx.store().delete_user_sessions(&user_id).await {
        Ok(_) => {
            tracing::info!(
                user_id = %authenticated.user.id,
                "All user sessions revoked"
            );

            HttpResponse::Ok()
                .cookie(build_removal_session_cookie())
                .json(json!({
                    "success": true
                }))
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "Failed to revoke user sessions"
            );

            HttpResponse::InternalServerError().finish()
        }
    }
}

// -------------------- Revoke Other Sessions - POST "/revoke-other-sessions" --------------------

#[tracing::instrument(name = "auth.revoke_other_sessions", skip_all)]
pub async fn revoke_other_sessions<D: AuthDatabase + 'static>(
    req: HttpRequest,
    ctx: web::Data<AuthrContext<D>>,
) -> impl Responder {
    let extensions = req.extensions();
    let Some(authenticated) = extensions.get::<AuthenticatedSession>() else {
        return HttpResponse::Unauthorized().finish();
    };

    // ----- Revoke other sessions
    let user_id = authenticated.user.id.to_string();
    let session_id = authenticated.session.id.to_string();

    match ctx
        .store()
        .delete_other_sessions(&user_id, &session_id)
        .await
    {
        Ok(_) => {
            tracing::info!(
                user_id = %authenticated.user.id,
                current_session_id = %authenticated.session.id,
                "Other user sessions revoked"
            );

            HttpResponse::Ok().json(json!({
                "success": true
            }))
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "Failed to revoke other sessions"
            );

            HttpResponse::InternalServerError().finish()
        }
    }
}
