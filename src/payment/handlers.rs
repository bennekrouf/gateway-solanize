// src/payment/handlers.rs - CLEANED UP to remove direct Solana calls

use rocket::{State, get, post, serde::json::Json};
use sqlx::SqlitePool;

use crate::{
    auth::User,
    config::AppConfig,
    error::AppResult,
    payment::service::PaymentService,
    types::{
        ConfirmTransactionRequest, CreateTransactionRequest, CreateTransactionResponse, Transaction,
    },
};

// Keep only local transaction management endpoints
#[post("/create", data = "<request>")]
pub async fn create_transaction(
    request: Json<CreateTransactionRequest>,
    user: User,
    pool: &State<SqlitePool>,
    config: &State<AppConfig>,
) -> AppResult<Json<CreateTransactionResponse>> {
    let payment_service = PaymentService::new(config);
    let response = payment_service
        .create_transaction(&user.id, &request.transaction_type, pool)
        .await?;

    Ok(Json(response))
}

#[post("/confirm", data = "<request>")]
pub async fn confirm_transaction(
    request: Json<ConfirmTransactionRequest>,
    user: User,
    pool: &State<SqlitePool>,
    config: &State<AppConfig>,
) -> AppResult<Json<Transaction>> {
    let payment_service = PaymentService::new(config);
    let transaction = payment_service
        .confirm_transaction(
            request.transaction_id,
            &user.id,
            &request.signed_transaction, // This would be the signature from chat flow
            pool,
        )
        .await?;

    Ok(Json(transaction))
}

#[get("/history")]
pub async fn get_history(
    user: User,
    pool: &State<SqlitePool>,
) -> AppResult<Json<Vec<Transaction>>> {
    let transactions = sqlx::query_as::<_, Transaction>(
        "SELECT id, user_id, transaction_type, amount, status, tx_hash, created_at 
         FROM transactions 
         WHERE user_id = ? 
         ORDER BY created_at DESC",
    )
    .bind(user.id.to_string())
    .fetch_all(pool.inner())
    .await?;

    Ok(Json(transactions))
}

#[get("/health")]
pub async fn health_check(_config: &State<AppConfig>) -> AppResult<Json<serde_json::Value>> {
    // Simple health check - no direct Solana calls
    Ok(Json(serde_json::json!({
        "payment_service": "healthy",
        "note": "Solana operations now handled via chat interface with API0"
    })))
}

// REMOVED ENDPOINTS:
// - check_balance (use chat: "what's my balance?")
// - get_wallet_tokens (use chat: "show my portfolio")
// - get_wallet_history (use chat: "show my transaction history")
// - get_pending_transactions (use chat: "any pending transactions?")
// - get_token_price (use chat: "what's the price of SOL?")
// - search_tokens (use chat: "find RAY token")
// - get_trading_context (automatically included in chat context)
