// src/api0/guards.rs
//
// Who is calling, when the call arrives through api0 rather than from the web
// app.
//
// The web app authenticates a wallet directly: the user signs a challenge and
// gets a JWT, so the caller *proves* who they are. An api0 tool call cannot work
// that way — the person is in Claude, their wallet is not there to sign
// anything, and api0 has no access to their key.
//
// So api0 *asserts* the identity instead. Every tool call carries the email of
// the person who made it, plus a shared secret proving the call really came from
// api0. That shifts the security boundary: the email header is trustworthy only
// because the secret is, which is why a missing or wrong secret is rejected
// before the email is even read. Without that check, anyone who can reach this
// endpoint could claim to be any user — and therefore operate any linked wallet.

use rocket::{
    http::Status,
    request::{FromRequest, Outcome},
    Request, State,
};
use sqlx::SqlitePool;

use crate::{error::AppError, types::User as UserType};

/// The shared secret api0 sends on every proxied call.
///
/// Read from the environment rather than the config file, matching api0's own
/// convention: the same value has to be set in both processes, and a value in a
/// committed config is a value in the git history.
fn expected_secret() -> Option<String> {
    std::env::var("API0_INTERNAL_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Compare without leaking length or position through timing.
fn secret_matches(presented: &str, expected: &str) -> bool {
    if presented.len() != expected.len() {
        return false;
    }
    presented
        .bytes()
        .zip(expected.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// A solanize user resolved from an api0-authenticated call.
///
/// Deliberately the same `UserType` the JWT guard produces: once identity is
/// established, a request from Claude and a request from the web app are the
/// same thing, and handlers should not have to care which door it came through.
#[derive(Debug, Clone)]
pub struct Api0User(pub UserType);

impl std::ops::Deref for Api0User {
    type Target = UserType;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The caller's email, once the shared secret has been verified.
///
/// Separate from [`Api0User`] because the linking endpoint needs it *before*
/// there is a user to resolve — that is the whole point of linking.
pub struct Api0Caller {
    pub email: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Api0Caller {
    type Error = AppError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let expected = match expected_secret() {
            Some(s) => s,
            // Fail closed. An unset secret must not mean "accept everything":
            // that would turn a missing environment variable into an open door
            // onto every linked wallet.
            None => {
                return Outcome::Error((
                    Status::ServiceUnavailable,
                    AppError::Internal(
                        "API0_INTERNAL_SECRET is not set — refusing api0 calls".to_string(),
                    ),
                ));
            }
        };

        let presented = req.headers().get_one("x-internal-secret").unwrap_or("");
        if !secret_matches(presented, &expected) {
            return Outcome::Error((
                Status::Unauthorized,
                AppError::Auth("Invalid internal secret".to_string()),
            ));
        }

        match req.headers().get_one("x-user-email") {
            Some(email) if !email.trim().is_empty() => Outcome::Success(Api0Caller {
                email: email.trim().to_lowercase(),
            }),
            _ => Outcome::Error((
                Status::Unauthorized,
                AppError::Auth("No caller identity on an api0 request".to_string()),
            )),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Api0User {
    type Error = AppError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let caller = match Api0Caller::from_request(req).await {
            Outcome::Success(c) => c,
            Outcome::Error(e) => return Outcome::Error(e),
            Outcome::Forward(f) => return Outcome::Forward(f),
        };

        let pool = match req.guard::<&State<SqlitePool>>().await {
            Outcome::Success(pool) => pool,
            _ => {
                return Outcome::Error((
                    Status::InternalServerError,
                    AppError::Internal("Missing database pool".to_string()),
                ));
            }
        };

        let row = sqlx::query_as::<_, UserType>(
            "SELECT u.id, u.wallet_address, u.created_at, u.is_premium
               FROM users u
               JOIN api0_identities a ON a.user_id = u.id
              WHERE a.user_email = ?",
        )
        .bind(&caller.email)
        .fetch_one(pool.inner())
        .await;

        match row {
            Ok(user) => Outcome::Success(Api0User(user)),
            // Authenticated as somebody api0 knows, but nobody here has claimed
            // that address yet. A setup step, not a rejection — the message has
            // to say so, because it is what a first-time user will hit.
            Err(_) => Outcome::Error((
                Status::Forbidden,
                AppError::Auth(
                    "This account is not linked to a wallet yet. Open solanize, connect your \
                     wallet, and use the code it gives you."
                        .to_string(),
                ),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::secret_matches;

    #[test]
    fn a_secret_matches_only_itself() {
        assert!(secret_matches("correct-horse", "correct-horse"));
        assert!(!secret_matches("correct-horse", "correct-hors3"));
        assert!(!secret_matches("", "correct-horse"));
        assert!(!secret_matches("correct-horse", ""));
    }

    #[test]
    fn a_prefix_is_not_a_match() {
        // The length check must come first, or a short guess could pass the
        // byte-wise comparison by running out early.
        assert!(!secret_matches("correct", "correct-horse"));
        assert!(!secret_matches("correct-horse-extra", "correct-horse"));
    }
}
