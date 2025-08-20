use chrono::Utc;
use rocket::State;
use sqlx::SqlitePool;
use std::time::Duration;
use uuid::Uuid;

use crate::config::ApiProviderConfig;
use crate::{
    config::AppConfig,
    error::{AppError, AppResult},
    types::{ChatSession, Message, MessageResponse},
};

pub struct ChatService<'a> {
    config: &'a AppConfig,
    client: reqwest::Client,
}

impl<'a> ChatService<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        // Use timeout from current provider or ollama
        let timeout = if config.chat.ai_provider == "ollama" {
            config.chat.ollama.timeout_seconds
        } else {
            config
                .chat
                .api_providers
                .get(&config.chat.ai_provider)
                .map(|p| p.timeout_seconds)
                .unwrap_or(30)
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    pub async fn create_session(
        &self,
        user_id: &Uuid,
        title: Option<String>,
        pool: &State<SqlitePool>,
    ) -> AppResult<ChatSession> {
        // Check session limit
        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM chat_sessions WHERE user_id = ?")
                .bind(user_id.to_string())
                .fetch_one(pool.inner())
                .await?;

        if session_count >= self.config.chat.max_sessions_per_user as i64 {
            return Err(AppError::Validation(format!(
                "Maximum {} sessions allowed per user",
                self.config.chat.max_sessions_per_user
            )));
        }

        let session_id = Uuid::new_v4();
        let now = Utc::now();
        let session_title =
            title.unwrap_or_else(|| format!("Chat {}", now.format("%Y-%m-%d %H:%M")));

        sqlx::query(
            "INSERT INTO chat_sessions (id, user_id, title, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(session_id.to_string())
        .bind(user_id.to_string())
        .bind(&session_title)
        .bind(now.to_rfc3339())
        .execute(pool.inner())
        .await?;

        Ok(ChatSession {
            id: session_id,
            user_id: *user_id,
            title: session_title,
            created_at: now,
        })
    }

    pub async fn send_message(
        &self,
        session_id: Uuid,
        user_id: &Uuid,
        content: &str,
        pool: &State<SqlitePool>,
    ) -> AppResult<MessageResponse> {
        let _session = sqlx::query_as::<_, ChatSession>(
            "SELECT id, user_id, title, created_at FROM chat_sessions WHERE id = ? AND user_id = ?",
        )
        .bind(session_id.to_string())
        .bind(user_id.to_string())
        .fetch_one(pool.inner())
        .await
        .map_err(|e| {
            tracing::error!("SESSION CHECK FAILED: {:?}", e);
            AppError::NotFound("Session not found".to_string())
        })?;

        let message_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE session_id = ?")
                .bind(session_id.to_string())
                .fetch_one(pool.inner())
                .await
                .map_err(|e| {
                    tracing::error!("MESSAGE COUNT FAILED: {:?}", e);
                    e
                })?;

        if message_count >= self.config.chat.max_messages_per_session as i64 {
            tracing::error!("MESSAGE LIMIT EXCEEDED");
            return Err(AppError::Validation(format!(
                "Maximum {} messages allowed per session",
                self.config.chat.max_messages_per_session
            )));
        }

        // Save user message
        let user_message = self
            .save_message(session_id, content, true, pool)
            .await
            .map_err(|e| {
                tracing::error!("SAVE USER MESSAGE FAILED: {:?}", e);
                e
            })?;

        // Get conversation history for context
        let conversation_history = self
            .get_conversation_history(session_id, pool)
            .await
            .map_err(|e| {
                tracing::error!("GET CONVERSATION HISTORY FAILED: {:?}", e);
                e
            })?;

        // Generate AI response using Ollama
        let ai_response = self
            .generate_ollama_response(content, &conversation_history)
            .await
            .map_err(|e| {
                tracing::error!("OI CALL FAILED: {:?}", e);
                e
            })?;

        // Save AI message
        // tracing::error!("=== SAVING AI MESSAGE ===");
        let ai_message = self
            .save_message(session_id, &ai_response, false, pool)
            .await
            .map_err(|e| {
                tracing::error!("SAVE AI MESSAGE FAILED: {:?}", e);
                e
            })?;

        Ok(MessageResponse {
            user_message,
            ai_message,
        })
    }

    async fn save_message(
        &self,
        session_id: Uuid,
        content: &str,
        is_user: bool,
        pool: &State<SqlitePool>,
    ) -> AppResult<Message> {
        let message_id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            "INSERT INTO messages (id, session_id, content, is_user, created_at) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(message_id.to_string())
        .bind(session_id.to_string())
        .bind(content)
        .bind(is_user)
        .bind(now.to_rfc3339())
        .execute(pool.inner())
        .await?;

        Ok(Message {
            id: message_id,
            session_id,
            content: content.to_string(),
            is_user,
            created_at: now,
        })
    }

    async fn get_conversation_history(
        &self,
        session_id: Uuid,
        pool: &State<SqlitePool>,
    ) -> AppResult<Vec<Message>> {
        let messages = sqlx::query_as::<_, Message>(
            "SELECT id, session_id, content, is_user, created_at 
             FROM messages 
             WHERE session_id = ? 
             ORDER BY created_at ASC 
             LIMIT 20", // Last 20 messages for context
        )
        .bind(session_id.to_string())
        .fetch_all(pool.inner())
        .await?;

        Ok(messages)
    }

    async fn generate_ollama_response(
        &self,
        user_message: &str,
        conversation_history: &[Message],
    ) -> AppResult<String> {
        if self.config.chat.ai_provider == "ollama" {
            return self.call_ollama(user_message, conversation_history).await;
        }

        let provider_config = self
            .config
            .chat
            .api_providers
            .get(&self.config.chat.ai_provider)
            .ok_or_else(|| {
                AppError::Internal(format!(
                    "Provider '{}' not configured",
                    self.config.chat.ai_provider
                ))
            })?;

        self.call_api_provider(user_message, conversation_history, provider_config)
            .await
    }

async fn call_api_provider(
    &self,
    user_message: &str,
    conversation_history: &[Message],
    config: &ApiProviderConfig,
) -> AppResult<String> {
    let payload = match self.config.chat.ai_provider.as_str() {
        "cohere" => {
            // Cohere format: message + chat_history
            let mut chat_history = Vec::new();
            for msg in conversation_history.iter().rev().take(10).rev() {
                let role = if msg.is_user { "USER" } else { "CHATBOT" };
                chat_history.push(serde_json::json!({
                    "role": role,
                    "message": msg.content
                }));
            }

            serde_json::json!({
                "model": config.model,
                "message": user_message,
                "chat_history": chat_history,
                "max_tokens": 1000,
                "preamble": "You are a specialized trading assistant. Only answer questions related to trading, finance, markets, investments, and economic analysis. For any other topics, politely respond that you only provide assistance with trading-related matters."
            })
        }
        _ => {
            // Standard format (Claude, OpenAI, etc.): messages array
            let mut messages = Vec::new();
            
            // Add system message first
            messages.push(serde_json::json!({
                "role": "system", 
                "content": "You are a specialized trading assistant. Only answer questions related to trading, finance, markets, investments, and economic analysis. For any other topics, politely respond that you only provide assistance with trading-related matters."
            }));
            
            // Add conversation history
            for msg in conversation_history.iter().rev().take(10).rev() {
                let role = if msg.is_user { "user" } else { "assistant" };
                messages.push(serde_json::json!({"role": role, "content": msg.content}));
            }
            messages.push(serde_json::json!({"role": "user", "content": user_message}));

            serde_json::json!({
                "model": config.model,
                "messages": messages,
                "max_tokens": 1000
            })
        }
    };

    tracing::info!("Calling API provider: {}", self.config.chat.ai_provider);
    tracing::info!("Request payload: {}", serde_json::to_string_pretty(&payload).unwrap_or_default());

    let response = self.client
        .post(&format!("{}{}", config.base_url, config.endpoint))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", config.api_key))
        .json(&payload)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("API unavailable: {}", e)))?;

    let response_text = response.text().await
        .map_err(|e| AppError::Internal(format!("Failed to read response: {}", e)))?;

    tracing::info!("Raw API response: {}", response_text);

    let json: serde_json::Value = serde_json::from_str(&response_text)
        .map_err(|e| AppError::Internal(format!("JSON parse failed: {}", e)))?;

    tracing::info!("Parsed JSON response: {}", serde_json::to_string_pretty(&json).unwrap_or_default());

    // Check for API errors
    if let Some(error) = json.get("error") {
        let error_msg = error.get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown API error");
        return Err(AppError::Internal(format!("API error: {}", error_msg)));
    }

    // Check for Cohere-style error (has id but no text field)
    if let Some(error_msg) = json.get("message").and_then(|m| m.as_str()) {
        if json.get("id").is_some() && json.get("text").is_none() {
            return Err(AppError::Internal(format!("API error: {}", error_msg)));
        }
    }

    tracing::info!("Trying to extract using path: {}", config.response_path);
    self.extract_response_content(&json, &config.response_path)
}

async fn call_ollama(&self, user_message: &str, conversation_history: &[Message]) -> AppResult<String> {
    let mut messages = Vec::new();
    
    // Add system message first
    messages.push(serde_json::json!({
        "role": "system", 
        "content": "You are a specialized trading assistant. Only answer questions related to trading, finance, markets, investments, and economic analysis. For any other topics, politely respond that you only provide assistance with trading-related matters."
    }));
    
    // Add conversation history (last 5 messages)
    for msg in conversation_history.iter().rev().take(5).rev() {
        let role = if msg.is_user { "user" } else { "assistant" };
        messages.push(serde_json::json!({"role": role, "content": msg.content}));
    }
    messages.push(serde_json::json!({"role": "user", "content": user_message}));

    let payload = serde_json::json!({
        "model": self.config.chat.ollama.model,
        "messages": messages,
        "stream": false
    });

    tracing::info!("Calling Ollama with payload: {}", serde_json::to_string_pretty(&payload).unwrap_or_default());

    let response = self.client
        .post(&format!("{}/api/chat", self.config.chat.ollama.url))
        .json(&payload)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Ollama unavailable: {}", e)))?;

    let response_text = response.text().await
        .map_err(|e| AppError::Internal(format!("Failed to read response: {}", e)))?;

    tracing::info!("Raw Ollama response: {}", response_text);

    let json: serde_json::Value = serde_json::from_str(&response_text)
        .map_err(|e| AppError::Internal(format!("JSON parse failed: {}", e)))?;
    
    // Ollama chat response structure: { "message": { "content": "..." } }
    let content = json["message"]["content"]
        .as_str()
        .ok_or_else(|| AppError::Internal("No content in Ollama response".to_string()))?;

    tracing::info!("Extracted Ollama content: {}", content);
    Ok(content.to_string())
}
    fn extract_response_content(&self, json: &serde_json::Value, path: &str) -> AppResult<String> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = json;

        tracing::info!(
            "Extracting response using path: {} (parts: {:?})",
            path,
            parts
        );

        for (i, part) in parts.iter().enumerate() {
            tracing::info!(
                "Processing part {}: '{}', current value type: {:?}",
                i,
                part,
                current
            );

            if let Ok(index) = part.parse::<usize>() {
                current = current.get(index).ok_or_else(|| {
                    tracing::error!(
                        "Failed to get array index {} from: {}",
                        index,
                        serde_json::to_string_pretty(current).unwrap_or_default()
                    );
                    AppError::Internal(format!(
                        "Invalid response path at index {}: {}",
                        index, part
                    ))
                })?;
            } else {
                current = current.get(part).ok_or_else(|| {
                    tracing::error!(
                        "Failed to get field '{}' from: {}",
                        part,
                        serde_json::to_string_pretty(current).unwrap_or_default()
                    );
                    AppError::Internal(format!("Invalid response path at field: {}", part))
                })?;
            }
        }

        let result = current.as_str().unwrap_or("No response").to_string();
        tracing::info!("Extracted content: {}", result);
        Ok(result)
    }

    /// Health check for Ollama service
    pub async fn health_check(&self) -> AppResult<bool> {
        if self.config.chat.ai_provider == "ollama" {
            let url = format!("{}/api/tags", self.config.chat.ollama.url);
            match self.client.get(&url).send().await {
                Ok(response) => Ok(response.status().is_success()),
                Err(_) => Ok(false),
            }
        } else {
            // Generic health check for API providers
            let provider_config = self
                .config
                .chat
                .api_providers
                .get(&self.config.chat.ai_provider);

            match provider_config {
                Some(config) => {
                    let url = format!("{}{}", config.base_url, config.endpoint);
                    // Try a minimal request to check if the API is reachable
                    match self.client.get(&url).send().await {
                        Ok(response) => Ok(response.status() != reqwest::StatusCode::NOT_FOUND),
                        Err(_) => Ok(false),
                    }
                }
                None => Ok(false),
            }
        }
    }

    /// List available Ollama models
    pub async fn list_models(&self) -> AppResult<Vec<String>> {
        let url = format!("{}/api/tags", self.config.chat.ollama.url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Ollama service unavailable: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::Internal(
                "Failed to fetch Ollama models".to_string(),
            ));
        }

        // Parse Ollama tags response
        let tags_response: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid Ollama tags response: {}", e)))?;

        let models = tags_response["models"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|model| model["name"].as_str().map(|s| s.to_string()))
            .collect();

        Ok(models)
    }

    pub async fn delete_session(
        &self,
        session_id: Uuid,
        user_id: &Uuid,
        pool: &State<SqlitePool>,
    ) -> AppResult<()> {
        // Verify session belongs to user and exists
        let _session = sqlx::query_as::<_, ChatSession>(
            "SELECT id, user_id, title, created_at FROM chat_sessions WHERE id = ? AND user_id = ?",
        )
        .bind(session_id.to_string())
        .bind(user_id.to_string())
        .fetch_one(pool.inner())
        .await
        .map_err(|_| AppError::NotFound("Session not found or access denied".to_string()))?;

        // Delete session (cascade will handle messages due to foreign key)
        sqlx::query("DELETE FROM chat_sessions WHERE id = ? AND user_id = ?")
            .bind(session_id.to_string())
            .bind(user_id.to_string())
            .execute(pool.inner())
            .await?;

        tracing::info!("Session {} deleted by user {}", session_id, user_id);
        Ok(())
    }
}
