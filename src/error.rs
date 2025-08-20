use rocket::{Request, http::Status, response::Responder, response::Response, serde::json::Json};
use serde::Serialize;
use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    // #[error("Forbidden: {0}")]
    // Forbidden(String),
    #[error("Internal server error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl<'r> Responder<'r, 'static> for AppError {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        let (status, error_type) = match &self {
            AppError::Auth(_) => (Status::Unauthorized, "UNAUTHORIZED"),
            AppError::Validation(_) => (Status::BadRequest, "VALIDATION_ERROR"),
            AppError::NotFound(_) => (Status::NotFound, "NOT_FOUND"),
            // AppError::Forbidden(_) => (Status::Forbidden, "FORBIDDEN"),
            AppError::Database(_) | AppError::Internal(_) => {
                (Status::InternalServerError, "INTERNAL_ERROR")
            }
        };

        let error_response = ErrorResponse {
            error: error_type.to_string(),
            message: self.to_string(),
            details: None,
        };

        Response::build()
            .status(status)
            .header(rocket::http::ContentType::JSON)
            .sized_body(
                serde_json::to_string(&error_response).unwrap().len(),
                std::io::Cursor::new(serde_json::to_string(&error_response).unwrap()),
            )
            .ok()
    }
}

// Error handlers for different status codes
pub mod handlers {
    use super::*;

    #[rocket::catch(401)]
    pub fn unauthorized() -> Json<ErrorResponse> {
        Json(ErrorResponse {
            error: "UNAUTHORIZED".to_string(),
            message: "Authentication required".to_string(),
            details: None,
        })
    }

    #[rocket::catch(403)]
    pub fn forbidden() -> Json<ErrorResponse> {
        Json(ErrorResponse {
            error: "FORBIDDEN".to_string(),
            message: "Access denied".to_string(),
            details: None,
        })
    }

    #[rocket::catch(404)]
    pub fn not_found() -> Json<ErrorResponse> {
        Json(ErrorResponse {
            error: "NOT_FOUND".to_string(),
            message: "Resource not found".to_string(),
            details: None,
        })
    }

    #[rocket::catch(500)]
    pub fn internal_error() -> Json<ErrorResponse> {
        Json(ErrorResponse {
            error: "INTERNAL_ERROR".to_string(),
            message: "Internal server error".to_string(),
            details: None,
        })
    }
}
