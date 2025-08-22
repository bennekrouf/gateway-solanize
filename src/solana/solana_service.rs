use crate::{
    config::AppConfig,
    error::{AppError, AppResult},
    types::{
        SolanaBalanceData, SolanaBalanceRequest, SolanaResponse,
        WalletTokensResponse, TransactionHistoryResponse,
        SolanaCreateTransactionRequest, SolanaTransactionData,
        SolanaSubmitRequest, SolanaSubmitData,
    },
};
use std::time::Duration;

pub struct SolanaService<'a> {
    config: &'a AppConfig,
    client: reqwest::Client,
}

impl<'a> SolanaService<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.payment.timeout_seconds))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    pub async fn get_balance(&self, wallet_address: &str) -> AppResult<SolanaBalanceData> {
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

    pub async fn get_wallet_tokens(&self, wallet_address: &str) -> AppResult<WalletTokensResponse> {
        let request = serde_json::json!({
            "pubkey": wallet_address
        });

        let url = format!("{}/api/v1/wallet/tokens", self.config.payment.solana_service_url);
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

    pub async fn prepare_sol_transfer(
        &self,
        payer_pubkey: &str,
        to_address: &str,
        amount: f64,
    ) -> AppResult<String> {
        let request = SolanaCreateTransactionRequest {
            payer_pubkey: payer_pubkey.to_string(),
            to_address: to_address.to_string(),
            amount,
        };

        let url = format!("{}/api/v1/transaction/prepare", self.config.payment.solana_service_url);
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
            .map_err(|e| AppError::Internal(format!("Invalid transaction response: {}", e)))?;

        if !solana_response.success {
            return Err(AppError::Internal(
                solana_response
                    .error
                    .unwrap_or_else(|| "Transaction preparation failed".to_string()),
            ));
        }

        let data = solana_response
            .data
            .ok_or_else(|| AppError::Internal("Missing transaction data".to_string()))?;

        Ok(data.unsigned_transaction)
    }

    pub async fn submit_transaction(&self, signed_transaction: &str) -> AppResult<SolanaSubmitData> {
        let request = SolanaSubmitRequest {
            signed_transaction: signed_transaction.to_string(),
        };

        let url = format!("{}/api/v1/transaction/submit", self.config.payment.solana_service_url);
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
            .map_err(|e| AppError::Internal(format!("Invalid submit response: {}", e)))?;

        if !solana_response.success {
            return Err(AppError::Internal(
                solana_response
                    .error
                    .unwrap_or_else(|| "Transaction submission failed".to_string()),
            ));
        }

        solana_response
            .data
            .ok_or_else(|| AppError::Internal("Missing submission data".to_string()))
    }

    pub async fn health_check(&self) -> AppResult<bool> {
        let url = format!("{}/api/v1/health", self.config.payment.solana_service_url);
        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    // Add other microservice methods as needed...
}
