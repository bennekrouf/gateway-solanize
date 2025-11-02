// src/payment/service.rs - REMOVED direct Solana calls that should go through API0
// Keep only the transaction confirmation logic that handles local database state

use crate::{
    config::AppConfig,
    error::{AppError, AppResult},
    types::{CreateTransactionResponse, Transaction},
};
use chrono::Utc;
use rocket::State;
use sqlx::SqlitePool;
use uuid::Uuid;

pub struct PaymentService<'a> {
    config: &'a AppConfig,
}

impl<'a> PaymentService<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        Self { config }
    }

    // REMOVED: All direct Solana service calls
    // These should now go through API0 via the chat interface

    // Keep only local transaction management
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

        // NOTE: Transaction preparation should now happen through chat interface with API0
        Ok(CreateTransactionResponse {
            transaction,
            unsigned_transaction: "SHOULD_BE_PREPARED_VIA_CHAT_API0".to_string(),
        })
    }

    pub async fn confirm_transaction(
        &self,
        transaction_id: Uuid,
        user_id: &Uuid,
        transaction_signature: &str, // Changed from signed_transaction to signature
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

        // Update transaction status - submission should have happened via chat/API0
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
