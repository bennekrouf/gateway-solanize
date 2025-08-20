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
            &request.signed_transaction,
            pool,
        )
        .await?;

    Ok(Json(transaction))
}

#[get("/balance/<wallet_address>")]
pub async fn check_balance(
    wallet_address: &str,
    _user: User, // Require authentication
    config: &State<AppConfig>,
) -> AppResult<Json<serde_json::Value>> {
    let payment_service = PaymentService::new(config);
    let balance_data = payment_service.check_balance(&wallet_address).await?;

    Ok(Json(serde_json::json!({
        "wallet": balance_data.pubkey,
        "balance": balance_data.balance,
        "token": balance_data.token
    })))
}

#[get("/health")]
pub async fn health_check(config: &State<AppConfig>) -> AppResult<Json<serde_json::Value>> {
    let payment_service = PaymentService::new(config);
    let solana_healthy = payment_service.health_check().await.unwrap_or(false);

    Ok(Json(serde_json::json!({
        "solana_service": {
            "url": config.payment.solana_service_url,
            "healthy": solana_healthy
        }
    })))
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
