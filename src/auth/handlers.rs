use crate::{
    auth::service::{AuthService, ChallengeStore},
    config::AppConfig,
    error::AppResult,
    types::{AuthResponse, VerifyRequest},
};
use rocket::{State, post, serde::json::Json};
use sqlx::SqlitePool;

#[post("/challenge/<wallet_address>")]
pub async fn challenge(
    wallet_address: &str,
    challenge_store: &State<ChallengeStore>,
    config: &State<AppConfig>,
) -> AppResult<Json<serde_json::Value>> {
    let auth_service = AuthService::new(config);
    let challenge = auth_service
        .generate_challenge(&wallet_address, challenge_store)
        .await?;

    Ok(Json(serde_json::json!({
        "challenge": challenge.message,
        "expires_in_minutes": config.auth.challenge_expires_minutes
    })))
}

#[post("/verify", data = "<request>")]
pub async fn verify(
    request: Json<VerifyRequest>,
    pool: &State<SqlitePool>,
    challenge_store: &State<ChallengeStore>,
    config: &State<AppConfig>,
) -> AppResult<Json<AuthResponse>> {
    let auth_service = AuthService::new(config);
    let response = auth_service
        .verify_signature(
            &request.wallet_address,
            &request.signature,
            &request.challenge,
            pool,
            challenge_store,
        )
        .await?;

    Ok(Json(response))
}

#[post("/refresh")]
pub async fn refresh(
    _user: crate::auth::User, // JWT guard validates and provides user
    config: &State<AppConfig>,
) -> AppResult<Json<serde_json::Value>> {
    let auth_service = AuthService::new(config);
    let new_token = auth_service.generate_jwt(&_user.wallet_address, &_user.id.to_string())?;

    Ok(Json(serde_json::json!({
        "jwt": new_token
    })))
}
