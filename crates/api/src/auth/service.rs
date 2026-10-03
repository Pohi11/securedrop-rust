//! Authentication business logic: registration, login, refresh-token rotation, logout.
//!
//! Handlers stay thin; everything security-sensitive lives here so it can be read top to bottom.

use chrono::{DateTime, SubsecRound, Utc};
use secrecy::SecretString;
use securedrop_common::{RegisterRequest, TokenResponse, UserResponse};
use serde_json::json;
use uuid::Uuid;

use super::{password::validate_password_policy, repo, tokens};
use crate::{
    audit::{AuditEvent, Outcome},
    error::{AppError, AppResult},
    middleware::client_meta::ClientMeta,
    state::AppState,
    users::{self, model::normalize_email},
};

pub async fn register(
    state: &AppState,
    req: RegisterRequest,
    client: &ClientMeta,
) -> AppResult<UserResponse> {
    let email = normalize_email(&req.email)?;
    validate_password_policy(&req.password, &email)?;
    let password = SecretString::from(req.password);

    let hash = state.hasher.hash(&password).await?;
    let quota =
        i64::try_from(state.config.uploads.default_user_quota).map_err(AppError::internal)?;

    let user = match users::repo::insert(&state.db, Uuid::now_v7(), &email, &hash, quota).await {
        Ok(user) => user,
        Err(err) if is_unique_violation(&err) => {
            // Trade-off: this tells a caller the address is registered (enumeration). Without an
            // email-verification flow there is no way to avoid it on sign-up; rate limiting on
            // /auth/* bounds how fast anyone can probe.
            return Err(AppError::Conflict("email is already registered".into()));
        }
        Err(err) => return Err(err.into()),
    };

    AuditEvent::new("auth.register", Outcome::Success)
        .actor(user.id)
        .target("user", user.id)
        .record(&state.db, client)
        .await;

    Ok(UserResponse {
        id: user.id,
        email: user.email,
        storage_quota_bytes: state.config.uploads.default_user_quota,
        storage_used_bytes: 0,
        created_at: user.created_at,
    })
}

pub async fn login(
    state: &AppState,
    email: &str,
    password: SecretString,
    client: &ClientMeta,
) -> AppResult<TokenResponse> {
    // Normalisation errors become InvalidCredentials too: don't hint at what was wrong.
    let Ok(email) = normalize_email(email) else {
        state.hasher.verify_dummy(&password).await?;
        return Err(AppError::InvalidCredentials);
    };

    let Some(user) = users::repo::find_by_email(&state.db, &email).await? else {
        // Unknown user: burn the same Argon2 time as a real check, so response timing
        // does not reveal which emails are registered.
        state.hasher.verify_dummy(&password).await?;
        AuditEvent::new("auth.login", Outcome::Failure)
            .metadata(json!({ "reason": "unknown_user" }))
            .record(&state.db, client)
            .await;
        return Err(AppError::InvalidCredentials);
    };

    let password_ok = state.hasher.verify(&password, &user.password_hash).await?;

    if user.is_locked(Utc::now()) {
        // Same response as a wrong password: telling an attacker "locked" confirms the
        // account exists and that their guessing is having an effect.
        AuditEvent::new("auth.login", Outcome::Denied)
            .actor(user.id)
            .metadata(json!({ "reason": "account_locked" }))
            .record(&state.db, client)
            .await;
        return Err(AppError::InvalidCredentials);
    }

    if !password_ok {
        let auth = &state.config.auth;
        users::repo::record_failed_login(
            &state.db,
            user.id,
            auth.max_failed_logins,
            auth.lockout_duration,
        )
        .await?;
        AuditEvent::new("auth.login", Outcome::Failure)
            .actor(user.id)
            .metadata(
                json!({ "reason": "bad_password", "failed_count": user.failed_login_count + 1 }),
            )
            .record(&state.db, client)
            .await;
        metrics::counter!("securedrop_auth_failures_total", "reason" => "bad_password")
            .increment(1);
        return Err(AppError::InvalidCredentials);
    }

    users::repo::reset_failed_logins(&state.db, user.id).await?;

    // A new login starts a new session (= refresh-token family).
    let session_id = Uuid::now_v7();
    // Truncate to microseconds: that is Postgres' TIMESTAMPTZ precision, so the value we return
    // is exactly the value stored (and returned again on every rotation).
    let refresh_expires_at = (Utc::now()
        + chrono::Duration::from_std(state.config.auth.refresh_token_ttl)
            .map_err(AppError::internal)?)
    .trunc_subsecs(6);
    let response = issue_tokens(
        state,
        user.id,
        session_id,
        refresh_expires_at,
        client,
        &state.db,
    )
    .await?;

    AuditEvent::new("auth.login", Outcome::Success)
        .actor(user.id)
        .metadata(json!({ "session_id": session_id }))
        .record(&state.db, client)
        .await;
    Ok(response)
}

/// Exchange a refresh token for a new access token **and a new refresh token** (rotation).
///
/// Reuse detection: each refresh token is single-use. If a token that was already exchanged
/// (or revoked) is presented again, either the legitimate client or an attacker holds a copy.
/// We can't tell which, so we revoke the whole session; both must log in again, and the
/// attacker loses access.
pub async fn refresh(
    state: &AppState,
    refresh_token: &str,
    client: &ClientMeta,
) -> AppResult<TokenResponse> {
    let token_hash = tokens::hash_token(refresh_token);
    let mut tx = state.db.begin().await?;

    let Some(row) = repo::find_for_update(&mut *tx, &token_hash).await? else {
        return Err(AppError::Unauthorized);
    };

    if row.used_at.is_some() || row.revoked_at.is_some() {
        repo::revoke_family(&mut *tx, row.user_id, row.family_id).await?;
        tx.commit().await?;
        // Also kill access tokens already minted for this session.
        state.revocations.revoke(&[row.family_id]).await?;

        AuditEvent::new("auth.refresh_token_reuse", Outcome::Denied)
            .actor(row.user_id)
            .metadata(json!({ "session_id": row.family_id }))
            .record(&state.db, client)
            .await;
        metrics::counter!("securedrop_auth_failures_total", "reason" => "refresh_reuse")
            .increment(1);
        return Err(AppError::Unauthorized);
    }

    if row.expires_at <= Utc::now() {
        return Err(AppError::Unauthorized);
    }

    repo::mark_used(&mut *tx, row.id).await?;
    // The new token inherits the original expiry: rotation does not extend the session, so a
    // stolen-and-rotated chain still dies at the absolute session lifetime.
    let response = issue_tokens(
        state,
        row.user_id,
        row.family_id,
        row.expires_at,
        client,
        &mut *tx,
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

/// Revoke the session the access token belongs to (refresh family + every access token in it).
pub async fn logout(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    client: &ClientMeta,
) -> AppResult<()> {
    repo::revoke_family(&state.db, user_id, session_id).await?;
    state.revocations.revoke(&[session_id]).await?;
    AuditEvent::new("auth.logout", Outcome::Success)
        .actor(user_id)
        .metadata(json!({ "session_id": session_id }))
        .record(&state.db, client)
        .await;
    Ok(())
}

/// Revoke every session for the user ("log out everywhere", e.g. after a lost laptop).
pub async fn logout_all(
    state: &AppState,
    user_id: Uuid,
    current_session: Uuid,
    client: &ClientMeta,
) -> AppResult<()> {
    let mut sessions = repo::revoke_all_for_user(&state.db, user_id).await?;
    if !sessions.contains(&current_session) {
        sessions.push(current_session);
    }
    state.revocations.revoke(&sessions).await?;
    AuditEvent::new("auth.logout_all", Outcome::Success)
        .actor(user_id)
        .metadata(json!({ "sessions_revoked": sessions.len() }))
        .record(&state.db, client)
        .await;
    Ok(())
}

async fn issue_tokens(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    refresh_expires_at: DateTime<Utc>,
    client: &ClientMeta,
    db: impl sqlx::PgExecutor<'_>,
) -> AppResult<TokenResponse> {
    let refresh_token = tokens::generate_token().map_err(AppError::internal)?;
    let token_hash = tokens::hash_token(&refresh_token);
    repo::insert(
        db,
        repo::NewRefreshToken {
            user_id,
            family_id: session_id,
            token_hash: &token_hash,
            expires_at: refresh_expires_at,
            user_agent: client.user_agent.as_deref(),
            client_ip: client.ip.as_deref(),
        },
    )
    .await?;

    let (access_token, _claims) = state.jwt.issue(user_id, session_id)?;
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: state.jwt.ttl().as_secs(),
        refresh_token,
        refresh_expires_at,
    })
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .is_some_and(|e| e.is_unique_violation())
}
