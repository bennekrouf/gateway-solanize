use crate::types::TokenPriceResponse;
use crate::types::TokenSearchResponse;
use crate::types::TransactionHistoryResponse;
use crate::types::WalletTokensResponse;
use crate::{
    config::AppConfig,
    error::{AppError, AppResult},
    types::{
        CreateTransactionResponse, PendingTransactionsResponse, SolanaBalanceData,
        SolanaBalanceRequest, SolanaCreateTransactionRequest, SolanaResponse, SolanaSubmitData,
        SolanaSubmitRequest, SolanaSwapData, SolanaSwapRequest, SolanaTransactionData, Transaction,
    },
};
use chrono::Utc;
use rocket::State;
use sqlx::SqlitePool;
use std::time::Duration;
use uuid::Uuid;

pub struct PaymentService<'a> {
    config: &'a AppConfig,
    client: reqwest::Client,
}

impl<'a> PaymentService<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.payment.timeout_seconds))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    pub async fn create_transaction(
        &self,
        user_id: &Uuid,
        transaction_type: &str,
        pool: &State<SqlitePool>,
    ) -> AppResult<CreateTransactionResponse> {
        let transaction_id = Uuid::new_v4();
        let now = Utc::now();

        let amount = match transaction_type {
            "premium_upgrade" => Some(self.config.payment.premium_price_sol),
            _ => None,
        };

        // Create local transaction record
        sqlx::query(
            "INSERT INTO transactions (id, user_id, transaction_type, amount, status, created_at) 
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(transaction_id.to_string())
        .bind(user_id.to_string())
        .bind(transaction_type)
        .bind(amount)
        .bind("pending")
        .bind(now.to_rfc3339())
        .execute(pool.inner())
        .await?;

        let transaction = Transaction {
            id: transaction_id,
            user_id: *user_id,
            transaction_type: transaction_type.to_string(),
            amount,
            status: "pending".to_string(),
            tx_hash: None,
            created_at: now,
        };

        // Get user's wallet address from auth context (would need to be passed)
        // For now, using placeholder - you'll need to pass user wallet from context
        let user_wallet = "USER_WALLET_ADDRESS_FROM_AUTH_CONTEXT";

        // Call Solana microservice to prepare transaction
        let unsigned_transaction = match transaction_type {
            "premium_upgrade" => {
                self.prepare_sol_transfer(
                    user_wallet,
                    &self.get_treasury_address(),
                    amount.unwrap_or(0.0),
                )
                .await?
            }
            "token_swap" => {
                // Example: swap SOL to USDC for premium features
                self.prepare_token_swap(user_wallet, "SOL", "USDC", amount.unwrap_or(0.0))
                    .await?
            }
            _ => {
                return Err(AppError::Validation(
                    "Unsupported transaction type".to_string(),
                ));
            }
        };

        Ok(CreateTransactionResponse {
            transaction,
            unsigned_transaction,
        })
    }

    pub async fn confirm_transaction(
        &self,
        transaction_id: Uuid,
        user_id: &Uuid,
        signed_transaction: &str,
        pool: &State<SqlitePool>,
    ) -> AppResult<Transaction> {
        // Get transaction and verify ownership
        let transaction = sqlx::query_as::<_, Transaction>(
            "SELECT id, user_id, transaction_type, amount, status, tx_hash, created_at 
             FROM transactions 
             WHERE id = ? AND user_id = ?",
        )
        .bind(transaction_id.to_string())
        .bind(user_id.to_string())
        .fetch_one(pool.inner())
        .await
        .map_err(|_| AppError::NotFound("Transaction not found".to_string()))?;

        if transaction.status != "pending" {
            return Err(AppError::Validation(
                "Transaction already processed".to_string(),
            ));
        }

        // Submit to Solana microservice
        let submit_result = self.submit_transaction(signed_transaction).await?;

        // Update transaction status based on Solana service response
        let status = if submit_result.status == "submitted" {
            "confirmed"
        } else {
            "failed"
        };

        sqlx::query("UPDATE transactions SET status = ?, tx_hash = ? WHERE id = ?")
            .bind(status)
            .bind(&submit_result.signature)
            .bind(transaction_id.to_string())
            .execute(pool.inner())
            .await?;

        // Handle success logic only if confirmed
        if status == "confirmed" {
            self.handle_transaction_success(&transaction, pool).await?;
        }

        // Return updated transaction
        let updated_transaction = sqlx::query_as::<_, Transaction>(
            "SELECT id, user_id, transaction_type, amount, status, tx_hash, created_at 
             FROM transactions 
             WHERE id = ?",
        )
        .bind(transaction_id.to_string())
        .fetch_one(pool.inner())
        .await?;

        Ok(updated_transaction)
    }

    /// Prepare SOL transfer via Solana microservice
    pub async fn prepare_sol_transfer(
        &self,
        payer_pubkey: &str,
        to_address: &str,
        amount: f64,
    ) -> AppResult<String> {
        tracing::info!(
            "Preparing SOL transfer: {} SOL from {} to {}",
            amount,
            payer_pubkey,
            to_address
        );

        let request = SolanaCreateTransactionRequest {
            payer_pubkey: payer_pubkey.to_string(),
            to_address: to_address.to_string(),
            amount,
        };

        let url = format!(
            "{}/api/v1/transaction/prepare",
            self.config.payment.solana_service_url
        );
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Solana service unavailable: {}", e)))?;

        let solana_response: SolanaResponse<SolanaTransactionData> = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid Solana service response: {}", e)))?;

        if !solana_response.success {
            return Err(AppError::Internal(
                solana_response
                    .error
                    .unwrap_or_else(|| "Unknown Solana service error".to_string()),
            ));
        }

        let data = solana_response
            .data
            .ok_or_else(|| AppError::Internal("Missing transaction data".to_string()))?;

        tracing::info!(
            "SOL transfer prepared, blockhash: {}",
            data.recent_blockhash
        );
        Ok(data.unsigned_transaction)
    }

    /// Prepare token swap via Solana microservice
    pub async fn prepare_token_swap(
        &self,
        payer_pubkey: &str,
        from_token: &str,
        to_token: &str,
        amount: f64,
    ) -> AppResult<String> {
        tracing::info!(
            "Preparing token swap: {} {} to {} for {}",
            amount,
            from_token,
            to_token,
            payer_pubkey
        );

        let request = SolanaSwapRequest {
            payer_pubkey: payer_pubkey.to_string(),
            from_token: from_token.to_string(),
            to_token: to_token.to_string(),
            amount,
        };

        let url = format!(
            "{}/api/v1/swap/prepare",
            self.config.payment.solana_service_url
        );
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Solana service unavailable: {}", e)))?;

        let solana_response: SolanaResponse<SolanaSwapData> = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid Solana service response: {}", e)))?;

        if !solana_response.success {
            return Err(AppError::Internal(
                solana_response
                    .error
                    .unwrap_or_else(|| "Unknown Solana service error".to_string()),
            ));
        }

        let data = solana_response
            .data
            .ok_or_else(|| AppError::Internal("Missing swap data".to_string()))?;

        tracing::info!(
            "Token swap prepared, expected output: {}, price impact: {}%",
            data.quote_info.expected_output,
            data.quote_info.price_impact * 100.0
        );
        Ok(data.unsigned_transaction)
    }

    /// Submit signed transaction to Solana microservice
    pub async fn submit_transaction(&self, signed_transaction: &str) -> AppResult<SolanaSubmitData> {
        tracing::info!("Submitting signed transaction to Solana microservice");

        let request = SolanaSubmitRequest {
            signed_transaction: signed_transaction.to_string(),
        };

        let url = format!(
            "{}/api/v1/transaction/submit",
            self.config.payment.solana_service_url
        );
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Solana service unavailable: {}", e)))?;

        let solana_response: SolanaResponse<SolanaSubmitData> = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid Solana service response: {}", e)))?;

        if !solana_response.success {
            return Err(AppError::Internal(
                solana_response
                    .error
                    .unwrap_or_else(|| "Transaction submission failed".to_string()),
            ));
        }

        let data = solana_response
            .data
            .ok_or_else(|| AppError::Internal("Missing submission data".to_string()))?;

        tracing::info!("Transaction submitted successfully: {}", data.signature);
        Ok(data)
    }

    /// Check wallet balance via Solana microservice
    pub async fn check_balance(&self, wallet_address: &str) -> AppResult<SolanaBalanceData> {
        let request = SolanaBalanceRequest {
            pubkey: wallet_address.to_string(),
        };

        let url = format!("{}/api/v1/balance", self.config.payment.solana_service_url);
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Solana service unavailable: {}", e)))?;

        let solana_response: SolanaResponse<SolanaBalanceData> = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid balance response: {}", e)))?;

        if !solana_response.success {
            return Err(AppError::Internal(
                solana_response
                    .error
                    .unwrap_or_else(|| "Balance check failed".to_string()),
            ));
        }

        solana_response
            .data
            .ok_or_else(|| AppError::Internal("Missing balance data".to_string()))
    }

    /// Get treasury wallet address for payments
    fn get_treasury_address(&self) -> String {
        // TODO: Load from config or environment
        "CompanyTreasuryWalletAddressHere123456789".to_string()
    }

    /// Handle successful transaction business logic
    async fn handle_transaction_success(
        &self,
        transaction: &Transaction,
        pool: &State<SqlitePool>,
    ) -> AppResult<()> {
        match transaction.transaction_type.as_str() {
            "premium_upgrade" => {
                // Upgrade user to premium
                sqlx::query("UPDATE users SET is_premium = ? WHERE id = ?")
                    .bind(true)
                    .bind(transaction.user_id.to_string())
                    .execute(pool.inner())
                    .await?;

                tracing::info!(
                    "User {} upgraded to premium via transaction {}",
                    transaction.user_id,
                    transaction.id
                );
            }
            _ => {
                tracing::info!(
                    "No post-transaction logic for type: {}",
                    transaction.transaction_type
                );
            }
        }

        Ok(())
    }

    /// Get transaction history for any wallet via Solana microservice
    pub async fn get_wallet_transaction_history(
        &self,
        wallet_address: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> AppResult<TransactionHistoryResponse> {
        let request = serde_json::json!({
            "wallet_address": wallet_address,
            "limit": limit.unwrap_or(50),
            "offset": offset.unwrap_or(0)
        });

        let url = format!(
            "{}/api/v1/transactions/history",
            self.config.payment.solana_service_url
        );
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Solana service unavailable: {}", e)))?;

        let solana_response: SolanaResponse<TransactionHistoryResponse> = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid history response: {}", e)))?;

        if !solana_response.success {
            return Err(AppError::Internal(
                solana_response
                    .error
                    .unwrap_or_else(|| "History fetch failed".to_string()),
            ));
        }

        solana_response
            .data
            .ok_or_else(|| AppError::Internal("Missing history data".to_string()))
    }

    /// Get pending transactions for a wallet
    pub async fn get_pending_transactions(
        &self,
        wallet_address: &str,
    ) -> AppResult<PendingTransactionsResponse> {
        let request = serde_json::json!({
            "wallet_address": wallet_address
        });

        let url = format!(
            "{}/api/v1/transactions/pending",
            self.config.payment.solana_service_url
        );
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Solana service unavailable: {}", e)))?;

        let solana_response: SolanaResponse<PendingTransactionsResponse> = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid pending response: {}", e)))?;

        if !solana_response.success {
            return Err(AppError::Internal(solana_response.error.unwrap_or_else(
                || "Pending transactions fetch failed".to_string(),
            )));
        }

        solana_response
            .data
            .ok_or_else(|| AppError::Internal("Missing pending transactions data".to_string()))
    }

    /// Get token prices via Solana microservice
    pub async fn get_token_prices(&self, tokens: &[String]) -> AppResult<TokenPriceResponse> {
        let request = serde_json::json!({
            "tokens": tokens
        });

        let url = format!("{}/api/v1/price", self.config.payment.solana_service_url);
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Solana service unavailable: {}", e)))?;

        let solana_response: SolanaResponse<TokenPriceResponse> = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid price response: {}", e)))?;

        if !solana_response.success {
            return Err(AppError::Internal(
                solana_response
                    .error
                    .unwrap_or_else(|| "Price fetch failed".to_string()),
            ));
        }

        solana_response
            .data
            .ok_or_else(|| AppError::Internal("Missing price data".to_string()))
    }

    /// Search tokens via Solana microservice
    pub async fn search_tokens(
        &self,
        query: &str,
        limit: Option<u32>,
    ) -> AppResult<TokenSearchResponse> {
        let request = serde_json::json!({
            "query": query,
            "limit": limit.unwrap_or(20)
        });

        let url = format!(
            "{}/api/v1/tokens/search",
            self.config.payment.solana_service_url
        );
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Solana service unavailable: {}", e)))?;

        let solana_response: SolanaResponse<TokenSearchResponse> = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid search response: {}", e)))?;

        if !solana_response.success {
            return Err(AppError::Internal(
                solana_response
                    .error
                    .unwrap_or_else(|| "Token search failed".to_string()),
            ));
        }

        solana_response
            .data
            .ok_or_else(|| AppError::Internal("Missing search data".to_string()))
    }

    /// Get wallet tokens with balances via Solana microservice
    pub async fn get_wallet_tokens(&self, wallet_address: &str) -> AppResult<WalletTokensResponse> {
        let request = serde_json::json!({
            "wallet_address": wallet_address
        });

        let url = format!(
            "{}/api/v1/wallet/tokens",
            self.config.payment.solana_service_url
        );
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Solana service unavailable: {}", e)))?;

        let solana_response: SolanaResponse<WalletTokensResponse> = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid wallet tokens response: {}", e)))?;

        if !solana_response.success {
            return Err(AppError::Internal(
                solana_response
                    .error
                    .unwrap_or_else(|| "Wallet tokens fetch failed".to_string()),
            ));
        }

        solana_response
            .data
            .ok_or_else(|| AppError::Internal("Missing wallet tokens data".to_string()))
    }

    /// Health check for Solana microservice
    pub async fn health_check(&self) -> AppResult<bool> {
        let url = format!("{}/api/v1/health", self.config.payment.solana_service_url);

        match self.client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    // Try to parse the response to ensure it's valid
                    let health_response: Result<SolanaResponse<String>, _> = response.json().await;
                    Ok(health_response.is_ok())
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }
}
