use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// User types
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub wallet_address: String,
    pub created_at: DateTime<Utc>,
    pub is_premium: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub wallet_address: String,
}

// Auth types
#[derive(Debug, Clone)]
pub struct Challenge {
    pub message: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub wallet_address: String,
    pub signature: String,
    pub challenge: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub jwt: String,
    pub user: User,
}

// Chat types
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ChatSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub title: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Message {
    pub id: Uuid,
    pub session_id: Uuid,
    pub content: String,
    pub is_user: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub title: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub user_message: Message,
    pub ai_message: Message,
}

// Payment types
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Transaction {
    pub id: Uuid,
    pub user_id: Uuid,
    pub transaction_type: String,
    pub amount: Option<f64>,
    pub status: String,
    pub tx_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTransactionRequest {
    pub transaction_type: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmTransactionRequest {
    pub transaction_id: Uuid,
    pub signed_transaction: String,
}

#[derive(Debug, Serialize)]
pub struct CreateTransactionResponse {
    pub transaction: Transaction,
    pub unsigned_transaction: String, // Base58 encoded transaction
}

// Solana service types (matching the actual API spec)
#[derive(Debug, Serialize)]
pub struct SolanaCreateTransactionRequest {
    pub payer_pubkey: String,
    pub to_address: String,
    pub amount: f64,
}

#[derive(Debug, Serialize)]
pub struct SolanaSwapRequest {
    pub payer_pubkey: String,
    pub from_token: String,
    pub to_token: String,
    pub amount: f64,
}

#[derive(Debug, Serialize)]
pub struct SolanaSubmitRequest {
    pub signed_transaction: String, // Base64 encoded
}

#[derive(Debug, Deserialize)]
pub struct SolanaResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SolanaTransactionData {
    pub unsigned_transaction: String, // Base64 encoded
    pub from: Option<String>,
    pub to: Option<String>,
    pub amount: Option<f64>,
    pub required_signers: Vec<String>,
    pub recent_blockhash: String,
}

#[derive(Debug, Deserialize)]
pub struct SolanaSwapData {
    pub unsigned_transaction: String,
    pub quote_info: QuoteInfo,
    pub required_signers: Vec<String>,
    pub recent_blockhash: String,
}

#[derive(Debug, Deserialize)]
pub struct QuoteInfo {
    pub expected_output: f64,
    pub price_impact: f64,
    pub route_steps: u32,
}

#[derive(Debug, Deserialize)]
pub struct SolanaSubmitData {
    pub signature: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct SolanaBalanceRequest {
    pub pubkey: String,
}

#[derive(Debug, Deserialize)]
pub struct SolanaBalanceData {
    pub pubkey: String,
    pub balance: f64,
    pub token: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,     // wallet address
    pub user_id: String, // UUID as string
    pub exp: usize,
    pub iat: usize,
}
