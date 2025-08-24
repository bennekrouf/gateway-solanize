// src/chat/api0_service.rs
use crate::{
    config::AppConfig,
    error::{AppError, AppResult},
    types::{ProposedActions, ProposedEndpoint},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct Api0Request {
    pub message: String,
    pub user_context: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct Api0Response {
    pub intent_detected: bool,
    pub intent_type: String,
    pub confidence_score: f64,
    pub extracted_parameters: serde_json::Value,
    pub proposed_endpoints: Vec<Api0Endpoint>,
    pub estimated_cost: Option<f64>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Api0Endpoint {
    pub endpoint: String,
    pub method: String,
    pub description: String,
    pub params: serde_json::Value,
    pub risk_level: String,
}

pub struct Api0Service<'a> {
    config: &'a AppConfig,
    client: reqwest::Client,
}

impl<'a> Api0Service<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    pub async fn analyze_message(
        &self,
        message: &str,
        user_context: &serde_json::Value,
    ) -> AppResult<Option<ProposedActions>> {
        // TODO: Replace with actual API0.ai call when ready
        /*
        let request = Api0Request {
            message: message.to_string(),
            user_context: user_context.clone(),
        };

        let response = self
            .client
            .post("https://api0.ai/analyze")
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("API0 service unavailable: {}", e)))?;

        let api0_response: Api0Response = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid API0 response: {}", e)))?;

        if !api0_response.intent_detected {
            return Ok(None);
        }

        let proposed_actions = ProposedActions {
            action_id: uuid::Uuid::new_v4().to_string(),
            intent_description: self.get_intent_description(&api0_response.intent_type),
            confidence_score: api0_response.confidence_score,
            endpoints_to_call: api0_response
                .proposed_endpoints
                .into_iter()
                .map(|ep| self.map_to_proposed_endpoint(ep))
                .collect(),
            estimated_cost: api0_response.estimated_cost,
            warnings: api0_response.warnings,
        };

        Ok(Some(proposed_actions))
        */

        // Placeholder implementation until API0 is ready
        self.placeholder_intent_detection(message, user_context)
            .await
    }

    // Placeholder until API0 is ready - maps common patterns to endpoints
    async fn placeholder_intent_detection(
        &self,
        message: &str,
        user_context: &serde_json::Value,
    ) -> AppResult<Option<ProposedActions>> {
        let message_lower = message.to_lowercase();
        let wallet_address = user_context["wallet_address"].as_str().unwrap_or("");

        // Balance check intent
        if message_lower.contains("balance") || message_lower.contains("how much") {
            return Ok(Some(ProposedActions {
                action_id: uuid::Uuid::new_v4().to_string(),
                intent_description: "Check wallet balance".to_string(),
                confidence_score: 0.95,
                endpoints_to_call: vec![ProposedEndpoint {
                    endpoint: "/solana/balance".to_string(),
                    method: "POST".to_string(),
                    description: "FAKE Need API0 call - Get current SOL balance".to_string(),
                    params: serde_json::json!({
                        "pubkey": wallet_address
                    }),
                    risk_level: "none".to_string(),
                }],
                estimated_cost: None,
                warnings: vec![],
            }));
        }

        // Portfolio/tokens intent
        if message_lower.contains("portfolio")
            || message_lower.contains("tokens")
            || message_lower.contains("holdings")
        {
            return Ok(Some(ProposedActions {
                action_id: uuid::Uuid::new_v4().to_string(),
                intent_description: "Check wallet token holdings".to_string(),
                confidence_score: 0.92,
                endpoints_to_call: vec![ProposedEndpoint {
                    endpoint: "/solana/wallet/tokens".to_string(),
                    method: "POST".to_string(),
                    description: "Get all tokens in wallet with balances".to_string(),
                    params: serde_json::json!({
                        "pubkey": wallet_address
                    }),
                    risk_level: "none".to_string(),
                }],
                estimated_cost: None,
                warnings: vec![],
            }));
        }

        // Transfer intent
        if (message_lower.contains("send") || message_lower.contains("transfer"))
            && message_lower.contains("sol")
        {
            // Extract recipient and amount (placeholder logic)
            let amount = self.extract_amount(&message_lower).unwrap_or(0.1);
            let recipient = self
                .extract_address(&message_lower)
                .unwrap_or("RECIPIENT_ADDRESS_TO_EXTRACT".to_string());

            return Ok(Some(ProposedActions {
                action_id: uuid::Uuid::new_v4().to_string(),
                intent_description: format!("Transfer {} SOL to another wallet", amount),
                confidence_score: 0.88,
                endpoints_to_call: vec![ProposedEndpoint {
                    endpoint: "/solana/transaction/prepare".to_string(),
                    method: "POST".to_string(),
                    description: "Prepare SOL transfer transaction".to_string(),
                    params: serde_json::json!({
                        "payer_pubkey": wallet_address,
                        "to_address": recipient,
                        "amount": amount
                    }),
                    risk_level: "high".to_string(),
                }],
                estimated_cost: Some(0.000005),
                warnings: vec![
                    "This will transfer real SOL from your wallet".to_string(),
                    "Transaction is irreversible once confirmed".to_string(),
                ],
            }));
        }

        // Swap intent
        if message_lower.contains("swap")
            || (message_lower.contains("buy") && message_lower.contains("sell"))
        {
            let from_token = self
                .extract_from_token(&message_lower)
                .unwrap_or("SOL".to_string());
            let to_token = self
                .extract_to_token(&message_lower)
                .unwrap_or("USDC".to_string());
            let amount = self.extract_amount(&message_lower).unwrap_or(1.0);

            return Ok(Some(ProposedActions {
                action_id: uuid::Uuid::new_v4().to_string(),
                intent_description: format!("Swap {} {} for {}", amount, from_token, to_token),
                confidence_score: 0.85,
                endpoints_to_call: vec![ProposedEndpoint {
                    endpoint: "/solana/swap/prepare".to_string(),
                    method: "POST".to_string(),
                    description: "Prepare token swap transaction".to_string(),
                    params: serde_json::json!({
                        "payer_pubkey": wallet_address,
                        "from_token": from_token,
                        "to_token": to_token,
                        "amount": amount
                    }),
                    risk_level: "medium".to_string(),
                }],
                estimated_cost: Some(0.000010),
                warnings: vec![
                    "Token swaps have price impact and slippage".to_string(),
                    "You may receive less tokens than expected".to_string(),
                ],
            }));
        }

        // Transaction history intent
        if message_lower.contains("history")
            || message_lower.contains("transactions")
            || message_lower.contains("activity")
        {
            return Ok(Some(ProposedActions {
                action_id: uuid::Uuid::new_v4().to_string(),
                intent_description: "View transaction history".to_string(),
                confidence_score: 0.93,
                endpoints_to_call: vec![ProposedEndpoint {
                    endpoint: "/solana/transactions/history".to_string(),
                    method: "POST".to_string(),
                    description: "Get recent transaction history".to_string(),
                    params: serde_json::json!({
                        "pubkey": wallet_address,
                        "limit": 20
                    }),
                    risk_level: "none".to_string(),
                }],
                estimated_cost: None,
                warnings: vec![],
            }));
        }

        // Price check intent
        if message_lower.contains("price") || message_lower.contains("cost") {
            let token = self
                .extract_token_for_price(&message_lower)
                .unwrap_or("SOL".to_string());

            return Ok(Some(ProposedActions {
                action_id: uuid::Uuid::new_v4().to_string(),
                intent_description: format!("Get current price of {}", token),
                confidence_score: 0.90,
                endpoints_to_call: vec![ProposedEndpoint {
                    endpoint: "/solana/price".to_string(),
                    method: "POST".to_string(),
                    description: "Get current token price in USD".to_string(),
                    params: serde_json::json!({
                        "token": token
                    }),
                    risk_level: "none".to_string(),
                }],
                estimated_cost: None,
                warnings: vec![],
            }));
        }

        Ok(None)
    }

    fn extract_amount(&self, message: &str) -> Option<f64> {
        // Simple regex-like extraction (placeholder)
        if let Some(pos) = message.find(char::is_numeric) {
            let rest = &message[pos..];
            let end = rest.find(char::is_alphabetic).unwrap_or(rest.len());
            rest[..end].trim().parse::<f64>().ok()
        } else {
            None
        }
    }

    fn extract_address(&self, message: &str) -> Option<String> {
        // Look for base58-like strings (placeholder)
        let words: Vec<&str> = message.split_whitespace().collect();
        words
            .iter()
            .find(|word| word.len() > 32 && word.chars().all(|c| c.is_alphanumeric()))
            .map(|s| s.to_string())
    }

    fn extract_from_token(&self, message: &str) -> Option<String> {
        if message.contains("sol") {
            Some("SOL".to_string())
        } else if message.contains("usdc") {
            Some("USDC".to_string())
        } else {
            None
        }
    }

    fn extract_to_token(&self, message: &str) -> Option<String> {
        // Look for "to" or "for" patterns
        if message.contains("to usdc") || message.contains("for usdc") {
            Some("USDC".to_string())
        } else if message.contains("to sol") || message.contains("for sol") {
            Some("SOL".to_string())
        } else {
            None
        }
    }

    fn extract_token_for_price(&self, message: &str) -> Option<String> {
        if message.contains("sol") {
            Some("SOL".to_string())
        } else if message.contains("usdc") {
            Some("USDC".to_string())
        } else if message.contains("ray") {
            Some("RAY".to_string())
        } else {
            None
        }
    }

    fn get_intent_description(&self, intent_type: &str) -> String {
        match intent_type {
            "balance" => "Check wallet balance".to_string(),
            "transfer" => "Transfer tokens to another wallet".to_string(),
            "swap" => "Exchange tokens via DEX".to_string(),
            "history" => "View transaction history".to_string(),
            "price" => "Get token price information".to_string(),
            "portfolio" => "Analyze wallet holdings".to_string(),
            _ => format!("Execute {} operation", intent_type),
        }
    }

    fn map_to_proposed_endpoint(&self, api0_endpoint: Api0Endpoint) -> ProposedEndpoint {
        ProposedEndpoint {
            endpoint: api0_endpoint.endpoint,
            method: api0_endpoint.method,
            description: api0_endpoint.description,
            params: api0_endpoint.params,
            risk_level: api0_endpoint.risk_level,
        }
    }
}

// Endpoint execution service - handles the actual API calls
pub struct EndpointExecutor<'a> {
    config: &'a AppConfig,
    client: reqwest::Client,
}

impl<'a> EndpointExecutor<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.payment.timeout_seconds))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    pub async fn execute_endpoint(
        &self,
        endpoint: &ProposedEndpoint,
    ) -> AppResult<serde_json::Value> {
        let url = format!(
            "{}{}",
            self.config.payment.solana_service_url, endpoint.endpoint
        );

        tracing::info!("Executing endpoint: {} {}", endpoint.method, url);
        tracing::info!(
            "Parameters: {}",
            serde_json::to_string_pretty(&endpoint.params).unwrap_or_default()
        );

        let response = match endpoint.method.as_str() {
            "GET" => self.client.get(&url).send().await,
            "POST" => self.client.post(&url).json(&endpoint.params).send().await,
            _ => {
                return Err(AppError::Internal(format!(
                    "Unsupported method: {}",
                    endpoint.method
                )));
            }
        }
        .map_err(|e| AppError::Internal(format!("Solana service unavailable: {}", e)))?;

        let response_text = response
            .text()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read response: {}", e)))?;

        let json: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| AppError::Internal(format!("Invalid JSON response: {}", e)))?;

        // Check if Solana service returned an error
        if let Some(success) = json.get("success").and_then(|v| v.as_bool()) {
            if !success {
                let error_msg = json
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error from Solana service");
                return Err(AppError::Internal(error_msg.to_string()));
            }
        }

        Ok(json)
    }
}
