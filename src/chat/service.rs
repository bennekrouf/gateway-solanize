use graflog::app_log;
use chrono::Utc;
use rocket::State;
use sqlx::SqlitePool;
use std::time::Duration;
use uuid::Uuid;

use crate::{
    config::AppConfig,
    error::{AppError, AppResult},
    types::{ChatSession, Message, MessageResponse, PreparedTransaction, SendMessageRequest},
};

// ── ChatService ───────────────────────────────────────────────────────────────

pub struct ChatService<'a> {
    config: &'a AppConfig,
    client: reqwest::Client,
}

impl<'a> ChatService<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        let timeout = config
            .chat
            .api_providers
            .get("claude")
            .map(|p| p.timeout_seconds)
            .unwrap_or(60);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    // ── Main entry point ──────────────────────────────────────────────────────

    pub async fn send_message_with_transactions(
        &self,
        session_id: Uuid,
        user_id: &Uuid,
        user_wallet: &str,
        request: &SendMessageRequest,
        pool: &State<SqlitePool>,
    ) -> AppResult<MessageResponse> {
        // If the user has already signed a transaction, submit it directly.
        // No Claude call needed — the intent is unambiguous.
        if let Some(signed_tx) = &request.signed_transaction {
            return self
                .handle_signed_transaction(
                    session_id,
                    &request.content,
                    signed_tx,
                    pool,
                )
                .await;
        }

        // Normal conversation: call Claude with solanize-mcp tools attached
        let history = self.get_conversation_history(session_id, pool).await?;
        let (ai_text, prepared_tx) = self
            .call_claude_with_mcp(&request.content, &history, user_wallet)
            .await?;

        let user_message = self
            .save_message(session_id, &request.content, true, pool)
            .await?;
        let ai_message = self
            .save_message(session_id, &ai_text, false, pool)
            .await?;

        Ok(MessageResponse {
            user_message,
            ai_message,
            prepared_transaction: prepared_tx,
        })
    }

    // ── Claude + MCP call ─────────────────────────────────────────────────────
    //
    // Uses the Anthropic Messages API beta with the solanize-mcp server attached.
    // Anthropic executes the full MCP tool loop server-side — one HTTP call is
    // enough; the response already contains the final text + tool results.

    async fn call_claude_with_mcp(
        &self,
        user_message: &str,
        history: &[Message],
        user_wallet: &str,
    ) -> AppResult<(String, Option<PreparedTransaction>)> {
        let claude_config = self
            .config
            .chat
            .api_providers
            .get("claude")
            .ok_or_else(|| AppError::Internal("Claude provider not configured".to_string()))?;

        // Build message history (last 20 turns for context)
        let mut messages: Vec<serde_json::Value> = history
            .iter()
            .rev()
            .take(20)
            .rev()
            .map(|m| {
                let role = if m.is_user { "user" } else { "assistant" };
                serde_json::json!({ "role": role, "content": m.content })
            })
            .collect();

        messages.push(serde_json::json!({ "role": "user", "content": user_message }));

        let system_prompt = format!(
            "You are a Solana blockchain assistant. The user's connected wallet is `{}`.\n\
             \n\
             You have access to Solana tools: check balances, token prices, transaction history,\n\
             portfolio, token search, and transaction preparation/submission.\n\
             \n\
             For transfers and swaps, use the prepare tools to create an unsigned transaction.\n\
             The user will sign it in their browser wallet — you do NOT need to submit it\n\
             yourself unless the user explicitly provides a signed transaction.\n\
             \n\
             Be concise and accurate. Format numbers clearly (e.g. 1.5 SOL, $42.30).",
            user_wallet
        );

        let payload = serde_json::json!({
            "model":      claude_config.model,
            "max_tokens": 2048,
            "system":     system_prompt,
            "messages":   messages,
            "mcp_servers": [{
                "type": "url",
                "url":  self.config.chat.solanize_mcp_url,
                "name": "solanize"
            }],
            "tools": [{
                "type":            "mcp_toolset",
                "mcp_server_name": "solanize"
            }]
        });

        app_log!(info, "Calling Claude with MCP (model: {})", claude_config.model);

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key",         &claude_config.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("anthropic-beta",    "mcp-client-2025-11-20")
            .header("content-type",      "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Claude API unavailable: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Claude API error {}: {}",
                status, body
            )));
        }

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse Claude response: {}", e)))?;

        self.parse_claude_response(&json)
    }

    // ── Parse response ────────────────────────────────────────────────────────
    //
    // Claude's response content array may contain:
    //  - { type: "text" }          → user-facing answer
    //  - { type: "mcp_tool_use" }  → which tool Claude called (informational)
    //  - { type: "mcp_tool_result" } → what the tool returned
    //
    // We collect all text blocks into the AI message, and scan tool results
    // for a `prepared_transaction` payload emitted by solana_prepare_transfer
    // or solana_prepare_swap.

    fn parse_claude_response(
        &self,
        json: &serde_json::Value,
    ) -> AppResult<(String, Option<PreparedTransaction>)> {
        let content = json
            .get("content")
            .and_then(|c| c.as_array())
            .ok_or_else(|| AppError::Internal("No content in Claude response".to_string()))?;

        let mut text_parts: Vec<String> = Vec::new();
        let mut prepared_tx: Option<PreparedTransaction> = None;

        for block in content {
            match block.get("type").and_then(|t| t.as_str()) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                        text_parts.push(t.to_string());
                    }
                }
                Some("mcp_tool_result") => {
                    // The solanize-mcp prepare tools embed a JSON object with
                    // action: "prepared_transaction" in their text result.
                    if let Some(arr) = block.get("content").and_then(|c| c.as_array()) {
                        for rb in arr {
                            if let Some(raw) = rb.get("text").and_then(|v| v.as_str()) {
                                if let Ok(obj) = serde_json::from_str::<serde_json::Value>(raw) {
                                    if obj.get("action").and_then(|v| v.as_str())
                                        == Some("prepared_transaction")
                                    {
                                        prepared_tx = Some(PreparedTransaction {
                                            transaction_id: Uuid::new_v4().to_string(),
                                            transaction_type: obj
                                                .get("transaction_type")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("transfer")
                                                .to_string(),
                                            unsigned_transaction: obj
                                                .get("unsigned_transaction")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("")
                                                .to_string(),
                                            from_address: obj
                                                .get("from_address")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("")
                                                .to_string(),
                                            to_address: obj
                                                .get("to_address")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("")
                                                .to_string(),
                                            amount: obj
                                                .get("amount")
                                                .and_then(|v| v.as_f64())
                                                .unwrap_or(0.0),
                                            token: obj
                                                .get("from_token")
                                                .or(obj.get("token"))
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("SOL")
                                                .to_string(),
                                            fee_estimate: Some(0.000005),
                                        });
                                        app_log!(
                                            info,
                                            "Extracted prepared_transaction (type: {})",
                                            prepared_tx
                                                .as_ref()
                                                .map(|t| t.transaction_type.as_str())
                                                .unwrap_or("unknown")
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                // mcp_tool_use blocks are informational — no action needed
                _ => {}
            }
        }

        let text = if text_parts.is_empty() {
            "I processed your request.".to_string()
        } else {
            text_parts.join("\n")
        };

        Ok((text, prepared_tx))
    }

    // ── Signed transaction submission ─────────────────────────────────────────
    //
    // The user has signed a prepared transaction in their browser wallet and sent
    // it back. We submit it directly to cli-solanize — no Claude call needed.

    async fn handle_signed_transaction(
        &self,
        session_id: Uuid,
        message_content: &str,
        signed_tx: &str,
        pool: &State<SqlitePool>,
    ) -> AppResult<MessageResponse> {
        let url = format!(
            "{}/solana/transaction/submit",
            self.config.payment.solana_service_url
        );
        let auth = format!("Bearer {}", self.config.payment.cli_internal_secret);

        app_log!(info, "Submitting signed transaction to cli-solanize");

        let result = self
            .client
            .post(&url)
            .header("Authorization", auth)
            .json(&serde_json::json!({ "signed_transaction": signed_tx }))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("cli-solanize unavailable: {}", e)))?;

        let json: serde_json::Value = result
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid cli response: {}", e)))?;

        let ai_response = if json.get("success").and_then(|v| v.as_bool()) == Some(true) {
            let sig = json
                .pointer("/data/signature")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!(
                "✅ Transaction submitted!\n\n\
                 Signature: `{sig}`\n\n\
                 [View on Solana Explorer](https://explorer.solana.com/tx/{sig})"
            )
        } else {
            let err = json
                .pointer("/data/error")
                .or_else(|| json.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            format!("❌ Transaction submission failed: {err}")
        };

        let user_message = self
            .save_message(session_id, message_content, true, pool)
            .await?;
        let ai_message = self
            .save_message(session_id, &ai_response, false, pool)
            .await?;

        Ok(MessageResponse {
            user_message,
            ai_message,
            prepared_transaction: None,
        })
    }

    // ── Session / message helpers ─────────────────────────────────────────────

    pub async fn create_session(
        &self,
        user_id: &Uuid,
        title: Option<String>,
        pool: &State<SqlitePool>,
    ) -> AppResult<ChatSession> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM chat_sessions WHERE user_id = ?")
                .bind(user_id.to_string())
                .fetch_one(pool.inner())
                .await?;

        if count >= self.config.chat.max_sessions_per_user as i64 {
            return Err(AppError::Validation(format!(
                "Maximum {} sessions allowed per user",
                self.config.chat.max_sessions_per_user
            )));
        }

        let session_id = Uuid::new_v4();
        let now = Utc::now();
        let title = title.unwrap_or_else(|| format!("Chat {}", now.format("%Y-%m-%d %H:%M")));

        sqlx::query(
            "INSERT INTO chat_sessions (id, user_id, title, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(session_id.to_string())
        .bind(user_id.to_string())
        .bind(&title)
        .bind(now.to_rfc3339())
        .execute(pool.inner())
        .await?;

        Ok(ChatSession {
            id: session_id,
            user_id: *user_id,
            title,
            created_at: now,
        })
    }

    async fn save_message(
        &self,
        session_id: Uuid,
        content: &str,
        is_user: bool,
        pool: &State<SqlitePool>,
    ) -> AppResult<Message> {
        let msg_id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            "INSERT INTO messages (id, session_id, content, is_user, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(msg_id.to_string())
        .bind(session_id.to_string())
        .bind(content)
        .bind(is_user)
        .bind(now.to_rfc3339())
        .execute(pool.inner())
        .await?;

        Ok(Message {
            id: msg_id,
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
            "SELECT id, session_id, content, is_user, created_at \
             FROM messages \
             WHERE session_id = ? \
             ORDER BY created_at ASC \
             LIMIT 20",
        )
        .bind(session_id.to_string())
        .fetch_all(pool.inner())
        .await?;

        Ok(messages)
    }

    pub async fn delete_session(
        &self,
        session_id: Uuid,
        user_id: &Uuid,
        pool: &State<SqlitePool>,
    ) -> AppResult<()> {
        sqlx::query_as::<_, ChatSession>(
            "SELECT id, user_id, title, created_at \
             FROM chat_sessions WHERE id = ? AND user_id = ?",
        )
        .bind(session_id.to_string())
        .bind(user_id.to_string())
        .fetch_one(pool.inner())
        .await
        .map_err(|_| AppError::NotFound("Session not found or access denied".to_string()))?;

        sqlx::query("DELETE FROM chat_sessions WHERE id = ? AND user_id = ?")
            .bind(session_id.to_string())
            .bind(user_id.to_string())
            .execute(pool.inner())
            .await?;

        app_log!(info, "Session {} deleted by user {}", session_id, user_id);
        Ok(())
    }

    // ── Health / model listing ────────────────────────────────────────────────

    pub async fn health_check(&self) -> AppResult<bool> {
        // Ping solanize-mcp /health.
        // solanize_mcp_url is the public URL (e.g. https://mcp.solanize.ai/mcp/<secret>);
        // strip the /mcp/<secret> suffix to get the base.
        let mcp_base = self
            .config
            .chat
            .solanize_mcp_url
            .split("/mcp/")
            .next()
            .unwrap_or("https://mcp.solanize.ai");

        match self
            .client
            .get(&format!("{}/health", mcp_base))
            .send()
            .await
        {
            Ok(r) => Ok(r.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    pub async fn list_models(&self) -> AppResult<Vec<String>> {
        // Return the configured Claude model
        let model = self
            .config
            .chat
            .api_providers
            .get("claude")
            .map(|p| p.model.clone())
            .unwrap_or_else(|| "claude-sonnet-4-20250514".to_string());
        Ok(vec![model])
    }
}
