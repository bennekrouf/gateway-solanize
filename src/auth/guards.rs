use rocket::{
    Request, State,
    http::Status,
    request::{FromRequest, Outcome},
};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::{
    auth::service::AuthService, config::AppConfig, error::AppError, types::User as UserType,
};

// Request guard for JWT authentication
pub struct User(pub UserType);

impl std::ops::Deref for User {
    type Target = UserType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = AppError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Get Authorization header
        let token = match req.headers().get_one("authorization") {
            Some(header) => {
                if header.starts_with("Bearer ") {
                    &header[7..]
                } else {
                    return Outcome::Error((
                        Status::Unauthorized,
                        AppError::Auth("Invalid authorization header format".to_string()),
                    ));
                }
            }
            None => {
                return Outcome::Error((
                    Status::Unauthorized,
                    AppError::Auth("Missing authorization header".to_string()),
                ));
            }
        };

        // Get dependencies
        let config = match req.guard::<&State<AppConfig>>().await {
            Outcome::Success(config) => config,
            _ => {
                return Outcome::Error((
                    Status::InternalServerError,
                    AppError::Internal("Missing config".to_string()),
                ));
            }
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

        // Verify JWT
        let auth_service = AuthService::new(config);
        let claims = match auth_service.verify_jwt(token) {
            Ok(claims) => claims,
            Err(e) => return Outcome::Error((Status::Unauthorized, e)),
        };

        // Get user from database
        let user_id = match Uuid::parse_str(&claims.user_id) {
            Ok(id) => id,
            Err(_) => {
                return Outcome::Error((
                    Status::Unauthorized,
                    AppError::Auth("Invalid user ID in token".to_string()),
                ));
            }
        };

        match sqlx::query_as::<_, UserType>(
            "SELECT id, wallet_address, created_at, is_premium FROM users WHERE id = ?",
        )
        .bind(user_id.to_string())
        .fetch_one(pool.inner())
        .await
        {
            Ok(user) => Outcome::Success(User(user)),
            Err(_) => Outcome::Error((
                Status::Unauthorized,
                AppError::Auth("User not found".to_string()),
            )),
        }
    }
}
