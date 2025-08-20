use rocket::{State, delete, get, post, serde::json::Json};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::{
    auth::User,
    chat::service::ChatService,
    config::AppConfig,
    error::AppResult,
    types::{ChatSession, CreateSessionRequest, Message, MessageResponse, SendMessageRequest},
};

#[post("/sessions", data = "<request>")]
pub async fn create_session(
    request: Json<CreateSessionRequest>,
    user: User,
    pool: &State<SqlitePool>,
    config: &State<AppConfig>,
) -> AppResult<Json<ChatSession>> {
    let chat_service = ChatService::new(config);
    let session = chat_service
        .create_session(&user.id, request.title.clone(), pool)
        .await?;
    Ok(Json(session))
}

#[get("/sessions")]
pub async fn get_sessions(
    user: User,
    pool: &State<SqlitePool>,
) -> AppResult<Json<Vec<ChatSession>>> {
    let sessions = sqlx::query_as::<_, ChatSession>(
        "SELECT id, user_id, title, created_at FROM chat_sessions WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(user.id.to_string())
    .fetch_all(pool.inner())
    .await?;

    Ok(Json(sessions))
}

#[post("/sessions/<session_id>/messages", data = "<request>")]
pub async fn send_message(
    session_id: Uuid,
    request: Json<SendMessageRequest>,
    user: User,
    pool: &State<SqlitePool>,
    config: &State<AppConfig>,
) -> AppResult<Json<MessageResponse>> {
    let chat_service = ChatService::new(config);
    let response = chat_service
        .send_message(session_id, &user.id, &request.content, pool)
        .await?;

    Ok(Json(response))
}

#[get("/sessions/<session_id>/messages")]
pub async fn get_messages(
    session_id: Uuid,
    user: User,
    pool: &State<SqlitePool>,
) -> AppResult<Json<Vec<Message>>> {
    // Verify session belongs to user
    let _session = sqlx::query_as::<_, ChatSession>(
        "SELECT id, user_id, title, created_at FROM chat_sessions WHERE id = ? AND user_id = ?",
    )
    .bind(session_id.to_string())
    .bind(user.id.to_string())
    .fetch_one(pool.inner())
    .await?;

    let messages = sqlx::query_as::<_, Message>(
        "SELECT id, session_id, content, is_user, created_at FROM messages WHERE session_id = ? ORDER BY created_at ASC"
    )
    .bind(session_id.to_string())
    .fetch_all(pool.inner())
    .await?;

    Ok(Json(messages))
}

#[get("/health")]
pub async fn chat_health(config: &State<AppConfig>) -> AppResult<Json<serde_json::Value>> {
    let chat_service = ChatService::new(config);
    let ai_healthy = chat_service.health_check().await.unwrap_or(false);

    let mut response = serde_json::json!({
        "ai_provider": config.chat.ai_provider,
        "healthy": ai_healthy
    });

    if config.chat.ai_provider == "ollama" {
        response["ollama"] = serde_json::json!({
            "url": config.chat.ollama.url,
            "model": config.chat.ollama.model,
            "healthy": ai_healthy
        });
    } else if let Some(provider_config) = config.chat.api_providers.get(&config.chat.ai_provider) {
        response["provider"] = serde_json::json!({
            "base_url": provider_config.base_url,
            "model": provider_config.model,
            "healthy": ai_healthy
        });
    }

    Ok(Json(response))
}

#[get("/models")]
pub async fn list_models(
    _user: User, // Require authentication
    config: &State<AppConfig>,
) -> AppResult<Json<serde_json::Value>> {
    let chat_service = ChatService::new(config);
    let models = chat_service.list_models().await.unwrap_or_else(|_| vec![]);

    let current_model = if config.chat.ai_provider == "ollama" {
        config.chat.ollama.model.clone()
    } else {
        config
            .chat
            .api_providers
            .get(&config.chat.ai_provider)
            .map(|p| p.model.clone())
            .unwrap_or_else(|| "unknown".to_string())
    };

    Ok(Json(serde_json::json!({
        "available_models": models,
        "current_model": current_model
    })))
}

#[delete("/sessions/<session_id>")]
pub async fn delete_session(
    session_id: Uuid,
    user: User,
    pool: &State<SqlitePool>,
    config: &State<AppConfig>, // Add this
) -> AppResult<Json<serde_json::Value>> {
    let chat_service = ChatService::new(config); // Use injected config
    chat_service
        .delete_session(session_id, &user.id, pool)
        .await?;

    Ok(Json(serde_json::json!({
        "message": "Session deleted successfully",
        "session_id": session_id
    })))
}
