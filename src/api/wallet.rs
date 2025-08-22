use rocket::{State, get, post, serde::json::Json};
use crate::{
    auth::User,
    solana::solana_service::SolanaService,
    config::AppConfig,
    error::AppResult,
    types::{WalletBalanceResponse, WalletTokensResponse, WalletHistoryRequest, TransactionHistoryResponse},
};

#[get("/balance")]
pub async fn get_balance(
    user: User,
    config: &State<AppConfig>,
) -> AppResult<Json<WalletBalanceResponse>> {
    let solana_service = SolanaService::new(config);
    let balance = solana_service.get_balance(&user.wallet_address).await?;
    
    Ok(Json(WalletBalanceResponse {
        wallet_address: user.wallet_address.clone(),
        balance: balance.balance,
        token: balance.token,
    }))
}

#[get("/tokens")]
pub async fn get_tokens(
    user: User,
    config: &State<AppConfig>,
) -> AppResult<Json<WalletTokensResponse>> {
    let solana_service = SolanaService::new(config);
    let tokens = solana_service.get_wallet_tokens(&user.wallet_address).await?;
    Ok(Json(tokens))
}

#[post("/history", data = "<request>")]
pub async fn get_history(
    request: Json<WalletHistoryRequest>,
    _user: User,
    config: &State<AppConfig>,
) -> AppResult<Json<TransactionHistoryResponse>> {
    let solana_service = SolanaService::new(config);
    let history = solana_service
        .get_transaction_history(&request.wallet_address, request.limit, request.offset)
        .await?;
    Ok(Json(history))
}

#[get("/health")]
pub async fn health_check(config: &State<AppConfig>) -> AppResult<Json<serde_json::Value>> {
    let solana_service = SolanaService::new(config);
    let healthy = solana_service.health_check().await.unwrap_or(false);
    
    Ok(Json(serde_json::json!({
        "solana_service": {
            "url": config.payment.solana_service_url,
            "healthy": healthy
        }
    })))
}
