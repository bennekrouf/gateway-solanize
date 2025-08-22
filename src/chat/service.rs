use chrono::Utc;
use rocket::State;
use sqlx::SqlitePool;
use std::time::Duration;
use uuid::Uuid;

use crate::payment::service::PaymentService;
use crate::config::ApiProviderConfig;
use crate::{
    config::AppConfig,
    error::{AppError, AppResult},
    types::{ChatSession, Message, MessageResponse},
};

use crate::types::ProposedEndpoint;
use crate::types::ActionResponse;
use crate::types::SendMessageRequest;
use crate::types::ProposedActions;
use crate::types::PreparedTransaction;
// use crate::types::ActionExecutionResult;
use crate::types::{TransactionRequest, ActionExecutionResult};

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

    async fn handle_signed_transaction(
        &self,
        session_id: Uuid,
        _user_id: &Uuid,
        _user_wallet: &str,
        message_content: &str,
        signed_transaction: &str,
        _transaction_id: Option<&str>,
        pool: &State<SqlitePool>,
    ) -> AppResult<MessageResponse> {
        let payment_service = PaymentService::new(self.config);
        
        let submission_result = payment_service
            .submit_transaction(signed_transaction)
            .await?;
        
        let ai_response = format!(
            "Transaction submitted successfully! Signature: {}. You can track it on Solana Explorer.",
            submission_result.signature
        );
        
        // Save messages
        let user_message = self.save_message(session_id, message_content, true, pool).await?;
        let ai_message = self.save_message(session_id, &ai_response, false, pool).await?;
        
        Ok(MessageResponse {
            user_message,
            ai_message,
            proposed_actions: None,
            prepared_transaction: None,
        })
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
            proposed_actions: None,
            prepared_transaction: None,
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

    pub async fn send_message_with_action_validation(
        &self,
        session_id: Uuid,
        user_id: &Uuid,
        user_wallet: &str,
        request: &SendMessageRequest,
        pool: &State<SqlitePool>,
    ) -> AppResult<MessageResponse> {
        // Handle user's response to proposed actions
        if let Some(action_response) = &request.action_response {
            return self
                .handle_action_response(session_id, user_id, user_wallet, action_response, pool)
                .await;
        }

        // Get trading context for both AI and API0
        let trading_context = self.get_trading_context(user_wallet).await?;

        // Send message to API0.ai to get proposed actions
        let proposed_actions = self
            .get_proposed_actions_from_api0(&request.content, user_wallet, &trading_context)
            .await?;

        // Generate AI response explaining the proposed actions
        let ai_response = if let Some(ref actions) = proposed_actions {
            self.generate_action_explanation_response(&request.content, actions)
                .await?
        } else {
            // Regular AI response for non-action messages
            self.generate_ai_response_with_context(
                &request.content,
                &self.get_conversation_history(session_id, pool).await?,
                &trading_context,
            )
            .await?
        };

        // Save messages
        let user_message = self
            .save_message(session_id, &request.content, true, pool)
            .await?;
        let ai_message = self
            .save_message(session_id, &ai_response, false, pool)
            .await?;

        Ok(MessageResponse {
            user_message,
            ai_message,
            proposed_actions, // Frontend will show these for user validation
            prepared_transaction: None,
        })
    }

    // Call API0.ai to analyze message and get proposed endpoints
    async fn get_proposed_actions_from_api0(
        &self,
        user_message: &str,
        user_wallet: &str,
        _trading_context: &serde_json::Value,
    ) -> AppResult<Option<ProposedActions>> {
        // TODO: Replace with actual API0.ai call
        //
        // let api0_request = Api0Request {
        //     message: user_message.to_string(),
        //     user_context: serde_json::json!({
        //         "wallet_address": user_wallet,
        //         "portfolio": trading_context
        //     })
        // };
        //
        // let response = self.client
        //     .post("https://api0.ai/analyze")
        //     .json(&api0_request)
        //     .send()
        //     .await?;
        //
        // let api0_response: Api0Response = response.json().await?;

        // Placeholder logic for development
        if user_message.to_lowercase().contains("send") && user_message.contains("sol") {
            return Ok(Some(ProposedActions {
                action_id: uuid::Uuid::new_v4().to_string(),
                intent_description: "Transfer SOL to another wallet".to_string(),
                confidence_score: 0.95,
                endpoints_to_call: vec![ProposedEndpoint {
                    endpoint: "/api/v1/transaction/prepare".to_string(),
                    method: "POST".to_string(),
                    description: "Prepare SOL transfer transaction".to_string(),
                    params: serde_json::json!({
                        "payer_pubkey": user_wallet,
                        "to_address": "EXTRACTED_FROM_MESSAGE", // TODO: Extract with API0
                        "amount": 1.0 // TODO: Extract with API0
                    }),
                    risk_level: "medium".to_string(),
                }],
                estimated_cost: Some(0.000005),
                warnings: vec!["This will transfer real SOL from your wallet".to_string()],
            }));
        }

        if user_message.to_lowercase().contains("balance") {
            return Ok(Some(ProposedActions {
                action_id: uuid::Uuid::new_v4().to_string(),
                intent_description: "Check wallet balance".to_string(),
                confidence_score: 0.99,
                endpoints_to_call: vec![ProposedEndpoint {
                    endpoint: "/api/v1/balance".to_string(),
                    method: "POST".to_string(),
                    description: "Get current SOL balance".to_string(),
                    params: serde_json::json!({
                        "pubkey": user_wallet
                    }),
                    risk_level: "none".to_string(),
                }],
                estimated_cost: None,
                warnings: vec![],
            }));
        }

        Ok(None)
    }

    // Generate AI explanation of proposed actions
    async fn generate_action_explanation_response(
        &self,
        _user_message: &str,
        actions: &ProposedActions,
    ) -> AppResult<String> {
        let action_summary = actions
            .endpoints_to_call
            .iter()
            .map(|ep| format!("• {}: {}", ep.method, ep.description))
            .collect::<Vec<_>>()
            .join("\n");

        let warning_text = if !actions.warnings.is_empty() {
            format!(
                "\n⚠️ Warnings:\n{}",
                actions
                    .warnings
                    .iter()
                    .map(|w| format!("• {}", w))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        } else {
            "".to_string()
        };

        let cost_text = if let Some(cost) = actions.estimated_cost {
            format!("\n💰 Estimated cost: {} SOL", cost)
        } else {
            "".to_string()
        };

        Ok(format!(
            "I understand you want to: {}\n\nProposed actions:\n{}{}{}\n\nConfidence: {:.0}%\n\nDo you want me to proceed with these actions?",
            actions.intent_description,
            action_summary,
            warning_text,
            cost_text,
            actions.confidence_score * 100.0
        ))
    }

    // Handle user's response to proposed actions (approve/reject)
    async fn handle_action_response(
        &self,
        session_id: Uuid,
        _user_id: &Uuid,
        user_wallet: &str,
        action_response: &ActionResponse,
        pool: &State<SqlitePool>,
    ) -> AppResult<MessageResponse> {
        let response_text = match action_response.approved {
            true => {
                // User approved - execute the actions
                let execution_result = self
                    .execute_approved_actions(
                        &action_response.action_id,
                        user_wallet,
                        &action_response.modified_params,
                    )
                    .await?;

                match execution_result {
                    ActionExecutionResult::PreparedTransaction(tx) => {
                        // Save messages and return prepared transaction for signing
                        let user_message = self
                            .save_message(session_id, "Approved actions", true, pool)
                            .await?;
                        let ai_message = self
                            .save_message(
                                session_id,
                                "Transaction prepared. Please review and sign.",
                                false,
                                pool,
                            )
                            .await?;

                        return Ok(MessageResponse {
                            user_message,
                            ai_message,
                            proposed_actions: None,
                            prepared_transaction: Some(tx),
                        });
                    }
                    ActionExecutionResult::DataResponse(data) => {
                        format!("Action completed successfully:\n{}", data)
                    }
                }
            }
            false => "Actions cancelled. How else can I help you?".to_string(),
        };

        // Save messages for approve/reject flow
        let user_message = self
            .save_message(
                session_id,
                &format!(
                    "Action response: {}",
                    if action_response.approved {
                        "Approved"
                    } else {
                        "Rejected"
                    }
                ),
                true,
                pool,
            )
            .await?;
        let ai_message = self
            .save_message(session_id, &response_text, false, pool)
            .await?;

        Ok(MessageResponse {
            user_message,
            ai_message,
            proposed_actions: None,
            prepared_transaction: None,
        })
    }

    // Execute approved actions
    async fn execute_approved_actions(
        &self,
        action_id: &str,
        user_wallet: &str,
        modified_params: &Option<serde_json::Value>,
    ) -> AppResult<ActionExecutionResult> {
        let payment_service = PaymentService::new(self.config);

        // TODO: In real implementation, look up stored actions by action_id
        // For now, determine action type from action_id or stored context

        // Example: If this was a transfer action
        if action_id.contains("transfer") {
            let default_params = serde_json::json!({});
            let params = modified_params.as_ref().unwrap_or(&default_params);
            let to_address = params["to_address"].as_str().unwrap_or("default");
            let amount = params["amount"].as_f64().unwrap_or(1.0);

            let unsigned_tx = payment_service
                .prepare_sol_transfer(user_wallet, to_address, amount)
                .await?;

            let prepared_tx = PreparedTransaction {
                transaction_id: uuid::Uuid::new_v4().to_string(),
                transaction_type: "transfer".to_string(),
                unsigned_transaction: unsigned_tx,
                from_address: user_wallet.to_string(),
                to_address: to_address.to_string(),
                amount,
                token: "SOL".to_string(),
                fee_estimate: Some(0.000005),
            };

            return Ok(ActionExecutionResult::PreparedTransaction(prepared_tx));
        }

        // Example: If this was a balance check
        if action_id.contains("balance") {
            let balance_data = payment_service.check_balance(user_wallet).await?;
            let response = format!("Your current balance: {} SOL", balance_data.balance);
            return Ok(ActionExecutionResult::DataResponse(response));
        }

        Err(AppError::Internal("Unknown action type".to_string()))
    }

    // Enhanced message sending with trading context
    pub async fn send_message_with_trading_context(
        &self,
        session_id: Uuid,
        user_id: &Uuid,
        user_wallet: &str, // Pass wallet address
        content: &str,
        pool: &State<SqlitePool>,
    ) -> AppResult<MessageResponse> {
        // Existing validation code...
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

        // Always get trading context for AI analysis
        let trading_context = self.get_trading_context(user_wallet).await?;

        // Save user message
        let user_message = self.save_message(session_id, content, true, pool).await?;

        // Get conversation history
        let conversation_history = self.get_conversation_history(session_id, pool).await?;

        // Generate AI response with trading context
        let ai_response = self
            .generate_ai_response_with_context(content, &conversation_history, &trading_context)
            .await?;

        // Save AI message
        let ai_message = self
            .save_message(session_id, &ai_response, false, pool)
            .await?;

        Ok(MessageResponse {
            user_message,
            ai_message,
            proposed_actions: None,
            prepared_transaction: None,
        })
    }

    // Check if query needs trading data
    fn is_trading_related_query(&self, content: &str) -> bool {
        let trading_keywords = [
            "portfolio",
            "tokens",
            "holdings",
            "balance",
            "trade",
            "buy",
            "sell",
            "price",
            "profit",
            "loss",
            "transaction",
            "swap",
            "investment",
            "recommendation",
            "advice",
            "analysis",
            "performance",
            "market",
        ];

        let content_lower = content.to_lowercase();
        trading_keywords
            .iter()
            .any(|&keyword| content_lower.contains(keyword))
    }

    // Get comprehensive trading context
    async fn get_trading_context(&self, wallet_address: &str) -> AppResult<serde_json::Value> {
        let solana_service = SolanaService::new(self.config);

        let portfolio = solana_service
            .get_wallet_tokens(wallet_address)
            .await?;

        let history = solana_service
            .get_transaction_history(wallet_address, Some(20), Some(0))
            .await?;

        // Get current prices for portfolio tokens
        let token_symbols: Vec<String> =
            portfolio.tokens.iter().map(|t| t.symbol.clone()).collect();

        let prices = if !token_symbols.is_empty() {
            solana_service.get_token_prices(&token_symbols).await.ok()
        } else {
            None
        };

        Ok(serde_json::json!({
            "wallet_address": wallet_address,
            "portfolio_summary": {
                "total_value_usd": portfolio.total_value_usd,
                "token_count": portfolio.tokens.len(),
                "top_holdings": portfolio.tokens.iter().take(5).collect::<Vec<_>>()
            },
            "recent_activity": {
                "transaction_count": history.transactions.len(),
                "recent_transactions": history.transactions.iter().take(5).collect::<Vec<_>>()
            },
            "market_data": prices
        }))
    }

    // Enhanced AI prompt with trading context
    async fn generate_ai_response_with_context(
        &self,
        user_message: &str,
        conversation_history: &[Message],
        trading_context: &serde_json::Value,
    ) -> AppResult<String> {
        // Build enhanced system prompt
        let mut system_prompt = "You are a specialized Solana trading assistant. Provide personalized trading advice based on the user's actual portfolio and transaction history.".to_string();

        system_prompt.push_str(&format!(
            "\n\nUSER'S CURRENT PORTFOLIO DATA:\n{}\n\nUse this data to provide specific, actionable advice. Reference their actual holdings and recent transactions when relevant.",
            serde_json::to_string_pretty(trading_context).unwrap_or_default()
        ));

        if self.config.chat.ai_provider == "ollama" {
            self.call_ollama_with_context(user_message, conversation_history, &system_prompt)
                .await
        } else {
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

            self.call_api_provider_with_context(
                user_message,
                conversation_history,
                provider_config,
                &system_prompt,
            )
            .await
        }
    }

    async fn call_api_provider_with_context(
        &self,
        user_message: &str,
        conversation_history: &[Message],
        config: &crate::config::ApiProviderConfig,
        system_prompt: &str,
    ) -> AppResult<String> {
        let payload = match self.config.chat.ai_provider.as_str() {
            "cohere" => {
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
                    "preamble": system_prompt
                })
            }
            _ => {
                let mut messages = Vec::new();
                messages.push(serde_json::json!({
                    "role": "system",
                    "content": system_prompt
                }));

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

        // Rest of the API call logic...
        let response = self
            .client
            .post(&format!("{}{}", config.base_url, config.endpoint))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", config.api_key))
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("API unavailable: {}", e)))?;

        let response_text = response
            .text()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read response: {}", e)))?;

        let json: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| AppError::Internal(format!("JSON parse failed: {}", e)))?;

        self.extract_response_content(&json, &config.response_path)
    }

    async fn call_ollama_with_context(
        &self,
        user_message: &str,
        conversation_history: &[Message],
        system_prompt: &str,
    ) -> AppResult<String> {
        let mut messages = Vec::new();

        // Enhanced system message with trading context
        messages.push(serde_json::json!({
            "role": "system",
            "content": system_prompt
        }));

        // Add conversation history
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

        let response = self
            .client
            .post(&format!("{}/api/chat", self.config.chat.ollama.url))
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Ollama unavailable: {}", e)))?;

        let response_text = response
            .text()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read response: {}", e)))?;

        let json: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| AppError::Internal(format!("JSON parse failed: {}", e)))?;

        let content = json["message"]["content"]
            .as_str()
            .ok_or_else(|| AppError::Internal("No content in Ollama response".to_string()))?;

        Ok(content.to_string())
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
        tracing::info!(
            "Request payload: {}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );

        let response = self
            .client
            .post(&format!("{}{}", config.base_url, config.endpoint))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", config.api_key))
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("API unavailable: {}", e)))?;

        let response_text = response
            .text()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read response: {}", e)))?;

        tracing::info!("Raw API response: {}", response_text);

        let json: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| AppError::Internal(format!("JSON parse failed: {}", e)))?;

        tracing::info!(
            "Parsed JSON response: {}",
            serde_json::to_string_pretty(&json).unwrap_or_default()
        );

        // Check for API errors
        if let Some(error) = json.get("error") {
            let error_msg = error
                .get("message")
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

    async fn call_ollama(
        &self,
        user_message: &str,
        conversation_history: &[Message],
    ) -> AppResult<String> {
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

        tracing::info!(
            "Calling Ollama with payload: {}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );

        let response = self
            .client
            .post(&format!("{}/api/chat", self.config.chat.ollama.url))
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Ollama unavailable: {}", e)))?;

        let response_text = response
            .text()
            .await
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

    fn parse_transaction_request(
        &self,
        _content: &str,
        _user_wallet: &str,
    ) -> Option<TransactionRequest> {
        // TODO: Remove when API0.ai is integrated
        None
    }

    pub async fn send_message_with_transactions(
        &self,
        session_id: Uuid,
        user_id: &Uuid,
        user_wallet: &str,
        request: &SendMessageRequest,
        pool: &State<SqlitePool>,
    ) -> AppResult<MessageResponse> {
        // Handle signed transaction submission
        if let Some(signed_tx) = &request.signed_transaction {
            return self
                .handle_signed_transaction(
                    session_id,
                    user_id,
                    user_wallet,
                    &request.content,
                    signed_tx,
                    request.transaction_id.as_deref(),
                    pool,
                )
                .await;
        }

        // Parse message for transaction requests
        let transaction_request = self.parse_transaction_request(&request.content, user_wallet);

        // Get trading context
        let trading_context = self.get_trading_context(user_wallet).await?;

        // Generate AI response with potential transaction
        let (ai_response, prepared_transaction) = if let Some(tx_request) = transaction_request {
            self.generate_response_with_transaction(
                &request.content,
                session_id,
                user_wallet,
                &tx_request,
                &trading_context,
                pool,
            )
            .await?
        } else {
            (
                self.generate_ai_response_with_context(
                    &request.content,
                    &self.get_conversation_history(session_id, pool).await?,
                    &trading_context
                )
                    .await?,
                None,
            )
        };

        // Save messages
        let user_message = self
            .save_message(session_id, &request.content, true, pool)
            .await?;
        let ai_message = self
            .save_message(session_id, &ai_response, false, pool)
            .await?;

        Ok(MessageResponse {
            user_message,
            ai_message,
            prepared_transaction,
            proposed_actions: None,
        })
    }

    async fn generate_response_with_transaction(
        &self,
        _content: &str,
        _session_id: Uuid,
        user_wallet: &str,
        tx_request: &TransactionRequest,
        _trading_context: &serde_json::Value,
        _pool: &State<SqlitePool>,
    ) -> AppResult<(String, Option<PreparedTransaction>)> {
        // Create transaction via Solana microservice
        let payment_service = PaymentService::new(self.config);
        
        let unsigned_transaction = match tx_request.tx_type.as_str() {
            "transfer" => {
                payment_service
                    .prepare_sol_transfer(user_wallet, &tx_request.to_address, tx_request.amount)
                    .await?
            }
            "swap" => {
                payment_service
                    .prepare_token_swap(
                        user_wallet,
                        &tx_request.from_token,
                        &tx_request.to_token,
                        tx_request.amount,
                    )
                    .await?
            }
            _ => {
                return Err(AppError::Validation(
                    "Unsupported transaction type".to_string(),
                ));
            }
        };

        // Create the PreparedTransaction struct
        let prepared_tx = PreparedTransaction {
            transaction_id: uuid::Uuid::new_v4().to_string(),
            transaction_type: tx_request.tx_type.clone(),
            unsigned_transaction, // This is the String from the payment service
            from_address: user_wallet.to_string(),
            to_address: tx_request.to_address.clone(),
            amount: tx_request.amount,
            token: tx_request.from_token.clone(),
            fee_estimate: Some(0.000005), // Typical SOL fee - could be dynamic
        };

        // Generate AI response explaining the transaction
        let ai_response = format!(
            "I'll prepare a {} of {} {} to {}. Please review the details and sign if you approve.",
            tx_request.tx_type, tx_request.amount, tx_request.from_token, tx_request.to_address
        );
        
        Ok((ai_response, Some(prepared_tx)))
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
