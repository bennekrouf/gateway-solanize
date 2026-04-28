use graflog::app_log;
// src/payment/service.rs

use crate::{
    config::AppConfig,
    error::{AppError, AppResult},
    types::{CreateTransactionResponse, Transaction},
};
use chrono::Utc;
use rocket::State;
use sqlx::SqlitePool;
use std::time::Duration;
use uuid::Uuid;

pub struct PaymentService<'a> {
    config: &'a AppConfig,
}

impl<'a> PaymentService<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        Self { config }
    }

    // Direct Solana calls are handled by solanize-mcp (via Claude's tool loop).
    // This service manages only local transaction records and premium upgrades.
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

        // unsigned_transaction is populated by the chat endpoint via solanize-mcp
        Ok(CreateTransactionResponse {
            transaction,
            unsigned_transaction: String::new(),
        })
    }

    pub async fn confirm_transaction(
        &self,
        transaction_id: Uuid,
        user_id: &Uuid,
        transaction_signature: &str,
        pool: &State<SqlitePool>,
    ) -> AppResult<Transaction> {
        // Validate signature format (Solana signatures are 88-char base58)
        let sig_bytes = bs58::decode(transaction_signature)
            .into_vec()
            .map_err(|_| AppError::Validation("Invalid transaction signature format".to_string()))?;
        if sig_bytes.len() != 64 {
            return Err(AppError::Validation("Invalid transaction signature length".to_string()));
        }

        // H1 — Verify the transaction actually landed on-chain before granting anything
        self.verify_signature_on_chain(transaction_signature).await?;

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

        // Update transaction status
        sqlx::query("UPDATE transactions SET status = ?, tx_hash = ? WHERE id = ?")
            .bind("confirmed")
            .bind(transaction_signature)
            .bind(transaction_id.to_string())
            .execute(pool.inner())
            .await?;

        // Handle success logic
        self.handle_transaction_success(&transaction, pool).await?;

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

    /// H1 — Verify a Solana transaction signature is confirmed on-chain.
    /// Calls the Solana JSON-RPC `getSignatureStatuses` method directly via HTTP.
    async fn verify_signature_on_chain(&self, signature: &str) -> AppResult<()> {
        let rpc_url = &self.config.payment.solana_rpc_url;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| AppError::Internal(format!("Failed to build HTTP client: {}", e)))?;

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignatureStatuses",
            "params": [[signature], {"searchTransactionHistory": true}]
        });

        let resp = client
            .post(rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Solana RPC unreachable: {}", e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid RPC response: {}", e)))?;

        let status = json
            .pointer("/result/value/0")
            .ok_or_else(|| AppError::Validation("Transaction not found on chain".to_string()))?;

        if status.is_null() {
            return Err(AppError::Validation(
                "Transaction not found on chain — it may not have been submitted".to_string(),
            ));
        }

        if let Some(err) = status.get("err") {
            if !err.is_null() {
                return Err(AppError::Validation(format!(
                    "Transaction failed on chain: {:?}",
                    err
                )));
            }
        }

        let confirmation = status
            .get("confirmationStatus")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if confirmation != "confirmed" && confirmation != "finalized" {
            return Err(AppError::Validation(format!(
                "Transaction not yet confirmed (status: {}). Try again shortly.",
                confirmation
            )));
        }

        app_log!(info, "Transaction {} verified on-chain ({})", signature, confirmation);
        Ok(())
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

                app_log!(info, 
                    "User {} upgraded to premium via transaction {}",
                    transaction.user_id,
                    transaction.id
                );
            }
            _ => {
                app_log!(info, 
                    "No post-transaction logic for type: {}",
                    transaction.transaction_type
                );
            }
        }

        Ok(())
    }
}
