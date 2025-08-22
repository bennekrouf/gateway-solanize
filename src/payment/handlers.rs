use rocket::{State, get, post, serde::json::Json};
use sqlx::SqlitePool;

use crate::{
    auth::User,
    config::AppConfig,
    error::AppResult,
    payment::service::PaymentService,
    types::{
        ConfirmTransactionRequest,
        CreateTransactionRequest,
        CreateTransactionResponse,
        PendingTransactionsResponse,
        TokenPriceRequest,
        TokenPriceResponse,
        TokenSearchRequest,
        TokenSearchResponse,
        Transaction,
        TransactionHistoryResponse,
        // Add new request/response types
        WalletHistoryRequest,
        WalletPendingRequest,
        WalletTokensRequest,
        WalletTokensResponse,
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

#[post("/trading-context")]
pub async fn get_trading_context(
    user: User,
    config: &State<AppConfig>,
) -> AppResult<Json<serde_json::Value>> {
    let payment_service = PaymentService::new(config);

    // Get all data AI needs for trading advice
    let portfolio = payment_service
        .get_wallet_tokens(&user.wallet_address)
        .await?;

    let history = payment_service
        .get_wallet_transaction_history(&user.wallet_address, Some(50), Some(0))
        .await?;

    // Get prices for tokens in portfolio
    let token_symbols: Vec<String> = portfolio.tokens.iter().map(|t| t.symbol.clone()).collect();

    let prices = if !token_symbols.is_empty() {
        Some(payment_service.get_token_prices(&token_symbols).await?)
    } else {
        None
    };

    Ok(Json(serde_json::json!({
        "wallet_address": user.wallet_address,
        "portfolio": portfolio,
        "transaction_history": history,
        "current_prices": prices,
        "analysis_timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

#[post("/history", data = "<request>")]
pub async fn get_wallet_history(
    request: Json<WalletHistoryRequest>,
    _user: User,
    config: &State<AppConfig>,
) -> AppResult<Json<TransactionHistoryResponse>> {
    let payment_service = PaymentService::new(config);
    let history = payment_service
        .get_wallet_transaction_history(&request.wallet_address, request.limit, request.offset)
        .await?;
    Ok(Json(history))
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

// NEW: Get pending transactions for a wallet
#[post("/pending", data = "<request>")]
pub async fn get_pending_transactions(
    request: Json<WalletPendingRequest>,
    _user: User, // Require authentication
    config: &State<AppConfig>,
) -> AppResult<Json<PendingTransactionsResponse>> {
    let payment_service = PaymentService::new(config);
    let pending = payment_service
        .get_pending_transactions(&request.wallet_address)
        .await?;

    Ok(Json(pending))
}

// NEW: Get token prices
#[post("/price", data = "<request>")]
pub async fn get_token_price(
    request: Json<TokenPriceRequest>,
    _user: User, // Require authentication
    config: &State<AppConfig>,
) -> AppResult<Json<TokenPriceResponse>> {
    let payment_service = PaymentService::new(config);
    let prices = payment_service.get_token_prices(&request.tokens).await?;

    Ok(Json(prices))
}

// NEW: Search tokens
#[post("/tokens/search", data = "<request>")]
pub async fn search_tokens(
    request: Json<TokenSearchRequest>,
    _user: User, // Require authentication
    config: &State<AppConfig>,
) -> AppResult<Json<TokenSearchResponse>> {
    let payment_service = PaymentService::new(config);
    let results = payment_service
        .search_tokens(&request.query, request.limit)
        .await?;

    Ok(Json(results))
}

// NEW: Get wallet tokens with balances
#[post("/wallet/tokens", data = "<request>")]
pub async fn get_wallet_tokens(
    request: Json<WalletTokensRequest>,
    _user: User, // Require authentication
    config: &State<AppConfig>,
) -> AppResult<Json<WalletTokensResponse>> {
    let payment_service = PaymentService::new(config);
    let tokens = payment_service
        .get_wallet_tokens(&request.wallet_address)
        .await?;

    Ok(Json(tokens))
}
