// src/api0/handlers.rs
//
// Binding an api0 account to a wallet.
//
//   POST /api/v1/link/code    (wallet JWT)     → a short code
//   POST /api/v1/link/redeem  (api0)           → binds the caller's email
//   GET  /api/v1/link/me      (api0)           → which wallet the caller is
//   DELETE /api/v1/link/me    (api0)           → unbind
//
// The direction matters. The code is minted in solanize, where the person has
// already proved they hold the wallet by signing a challenge; it is redeemed
// from Claude, where api0 vouches for their email. So each half of the binding
// is asserted by whoever can actually prove it, and neither side has to trust a
// claim the other could not verify.

use chrono::{Duration, Utc};
use rand::Rng;
use rocket::{delete, get, post, serde::json::Json, State};
use sqlx::SqlitePool;

use crate::{
    api0::guards::{Api0Caller, Api0User},
    auth::guards::User,
    error::{AppError, AppResult},
};

/// Six characters from an alphabet with no look-alikes: this gets read off one
/// screen and typed into another, so 0/O and 1/I would cost more than the extra
/// entropy is worth.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Long enough to walk to the other window, short enough that a code left on a
/// shared screen stops being useful.
const CODE_TTL_MINUTES: i64 = 10;

fn new_code() -> String {
    let mut rng = rand::thread_rng();
    (0..6)
        .map(|_| CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())] as char)
        .collect()
}

// ── POST /api/v1/link/code ───────────────────────────────────────────────────

/// Mint a code for the wallet-authenticated user looking at solanize.
#[post("/code")]
pub async fn create_link_code(
    user: User,
    pool: &State<SqlitePool>,
) -> AppResult<Json<serde_json::Value>> {
    let now = Utc::now();

    // Sweep expired codes on the way in; nothing else ever reads them.
    let _ = sqlx::query("DELETE FROM api0_link_codes WHERE expires_at < ?")
        .bind(now.to_rfc3339())
        .execute(pool.inner())
        .await;

    let code = new_code();
    let expires_at = now + Duration::minutes(CODE_TTL_MINUTES);

    sqlx::query(
        "INSERT INTO api0_link_codes (code, user_id, created_at, expires_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&code)
    .bind(user.0.id.to_string())
    .bind(now.to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .execute(pool.inner())
    .await?;

    Ok(Json(serde_json::json!({
        "code": code,
        "expires_at": expires_at.to_rfc3339(),
        "expires_in_minutes": CODE_TTL_MINUTES,
    })))
}

#[derive(serde::Deserialize)]
pub struct RedeemRequest {
    pub code: String,
}

// ── POST /api/v1/link/redeem ─────────────────────────────────────────────────

/// Redeem a code, binding the calling api0 email to the wallet that minted it.
///
/// Takes [`Api0Caller`] rather than [`Api0User`] on purpose: there is no link
/// yet, so requiring one would make this endpoint impossible to reach.
#[post("/redeem", data = "<request>")]
pub async fn redeem_link_code(
    caller: Api0Caller,
    request: Json<RedeemRequest>,
    pool: &State<SqlitePool>,
) -> AppResult<Json<serde_json::Value>> {
    let code = request.code.trim().to_uppercase();
    let now = Utc::now();

    // The DELETE is the redemption: a code works once, so a replay finds
    // nothing rather than binding a second account to the same wallet.
    let row: Option<(String,)> = sqlx::query_as(
        "DELETE FROM api0_link_codes WHERE code = ? AND expires_at > ? RETURNING user_id",
    )
    .bind(&code)
    .bind(now.to_rfc3339())
    .fetch_optional(pool.inner())
    .await?;

    let user_id = match row {
        Some((id,)) => id,
        None => {
            return Err(AppError::Auth(
                "That code is not valid — it may have expired. Ask solanize for a new one."
                    .to_string(),
            ));
        }
    };

    // Re-linking replaces: somebody moving to a new wallet should not have to
    // unlink first, and an email binds to exactly one wallet at a time.
    sqlx::query(
        "INSERT INTO api0_identities (user_email, user_id, linked_at)
         VALUES (?, ?, ?)
         ON CONFLICT(user_email) DO UPDATE SET user_id = excluded.user_id,
                                               linked_at = excluded.linked_at",
    )
    .bind(&caller.email)
    .bind(&user_id)
    .bind(now.to_rfc3339())
    .execute(pool.inner())
    .await?;

    let wallet: (String,) = sqlx::query_as("SELECT wallet_address FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(pool.inner())
        .await?;

    Ok(Json(serde_json::json!({
        "linked": true,
        "wallet_address": wallet.0,
    })))
}

// ── GET /api/v1/link/me ──────────────────────────────────────────────────────

/// Which wallet the calling api0 account operates.
///
/// Worth having beyond curiosity: it is the one call that proves the whole
/// chain — api0's secret, the email header, and the binding — without moving
/// any funds.
#[get("/me")]
pub async fn linked_wallet(user: Api0User) -> AppResult<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({
        "wallet_address": user.0.wallet_address,
        "is_premium": user.0.is_premium,
    })))
}

// ── DELETE /api/v1/link/me ───────────────────────────────────────────────────

/// Unbind this api0 account from its wallet.
#[delete("/me")]
pub async fn unlink(
    caller: Api0Caller,
    pool: &State<SqlitePool>,
) -> AppResult<Json<serde_json::Value>> {
    let result = sqlx::query("DELETE FROM api0_identities WHERE user_email = ?")
        .bind(&caller.email)
        .execute(pool.inner())
        .await?;

    Ok(Json(serde_json::json!({
        "unlinked": result.rows_affected() > 0,
    })))
}

#[cfg(test)]
mod tests {
    use super::new_code;

    #[test]
    fn a_code_is_six_unambiguous_characters() {
        for _ in 0..50 {
            let c = new_code();
            assert_eq!(c.len(), 6);
            assert!(!c.contains(['0', 'O', '1', 'I']), "ambiguous char in {c}");
        }
    }

    #[test]
    fn codes_do_not_repeat() {
        assert_ne!(new_code(), new_code());
    }
}
