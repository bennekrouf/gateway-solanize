use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row};
use uuid::Uuid;

// Custom User struct with manual FromRow implementation
#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: Uuid,
    pub wallet_address: String,
    pub created_at: DateTime<Utc>,
    pub is_premium: bool,
}

impl<'r> FromRow<'r, sqlx::sqlite::SqliteRow> for User {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        let id_str: String = row.try_get("id")?;
        let id = Uuid::parse_str(&id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let created_at_str: String = row.try_get("created_at")?;
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            .with_timezone(&Utc);

        Ok(User {
            id,
            wallet_address: row.try_get("wallet_address")?,
            created_at,
            is_premium: row.try_get("is_premium")?,
        })
    }
}

// Do the same for other structs that have UUID fields
#[derive(Debug, Clone, Serialize)]
pub struct ChatSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub title: String,
    pub created_at: DateTime<Utc>,
}

impl<'r> FromRow<'r, sqlx::sqlite::SqliteRow> for ChatSession {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        let id_str: String = row.try_get("id")?;
        let id = Uuid::parse_str(&id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let user_id_str: String = row.try_get("user_id")?;
        let user_id =
            Uuid::parse_str(&user_id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let created_at_str: String = row.try_get("created_at")?;
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            .with_timezone(&Utc);

        Ok(ChatSession {
            id,
            user_id,
            title: row.try_get("title")?,
            created_at,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub id: Uuid,
    pub session_id: Uuid,
    pub content: String,
    pub is_user: bool,
    pub created_at: DateTime<Utc>,
}

impl<'r> FromRow<'r, sqlx::sqlite::SqliteRow> for Message {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        let id_str: String = row.try_get("id")?;
        let id = Uuid::parse_str(&id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let session_id_str: String = row.try_get("session_id")?;
        let session_id =
            Uuid::parse_str(&session_id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let created_at_str: String = row.try_get("created_at")?;
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            .with_timezone(&Utc);

        Ok(Message {
            id,
            session_id,
            content: row.try_get("content")?,
            is_user: row.try_get("is_user")?,
            created_at,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Transaction {
    pub id: Uuid,
    pub user_id: Uuid,
    pub transaction_type: String,
    pub amount: Option<f64>,
    pub status: String,
    pub tx_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl<'r> FromRow<'r, sqlx::sqlite::SqliteRow> for Transaction {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        let id_str: String = row.try_get("id")?;
        let id = Uuid::parse_str(&id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let user_id_str: String = row.try_get("user_id")?;
        let user_id =
            Uuid::parse_str(&user_id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let created_at_str: String = row.try_get("created_at")?;
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            .with_timezone(&Utc);

        Ok(Transaction {
            id,
            user_id,
            transaction_type: row.try_get("transaction_type")?,
            amount: row.try_get("amount")?,
            status: row.try_get("status")?,
            tx_hash: row.try_get("tx_hash")?,
            created_at,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub _wallet_address: String,
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

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub title: Option<String>,
}

// Types for the validation flow
#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub content: String,
    pub action_response: Option<ActionResponse>,
    pub signed_transaction: Option<String>,
    pub transaction_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ActionResponse {
    pub action_id: String,
    pub approved: bool,
    pub modified_params: Option<serde_json::Value>, // User can modify parameters
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub user_message: Message,
    pub ai_message: Message,
    pub proposed_actions: Option<ProposedActions>,
    pub prepared_transaction: Option<PreparedTransaction>,
}

#[derive(Debug, Serialize)]
pub struct ProposedActions {
    pub action_id: String,
    pub intent_description: String,
    pub confidence_score: f64,
    pub endpoints_to_call: Vec<ProposedEndpoint>,
    pub estimated_cost: Option<f64>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProposedEndpoint {
    pub endpoint: String,
    pub method: String,
    pub description: String,
    pub params: serde_json::Value,
    pub risk_level: String, // "none", "low", "medium", "high"
}

#[derive(Debug)]
pub enum ActionExecutionResult {
    PreparedTransaction(PreparedTransaction),
    DataResponse(String),
}

#[derive(Debug, Serialize)]
pub struct PreparedTransaction {
    pub transaction_id: String,
    pub transaction_type: String, // "transfer", "swap", etc.
    pub unsigned_transaction: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: f64,
    pub token: String,
    pub fee_estimate: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct OllamaResponseMessage {
    pub _role: String,
    pub _content: String,
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
    pub _from: Option<String>,
    pub _to: Option<String>,
    pub _amount: Option<f64>,
    pub _required_signers: Vec<String>,
    pub recent_blockhash: String,
}

#[derive(Debug, Deserialize)]
pub struct SolanaSwapData {
    pub unsigned_transaction: String,
    pub quote_info: QuoteInfo,
    pub _required_signers: Vec<String>,
    pub _recent_blockhash: String,
}

#[derive(Debug, Deserialize)]
pub struct QuoteInfo {
    pub expected_output: f64,
    pub price_impact: f64,
    pub _route_steps: u32,
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

#[derive(Debug, Deserialize)]
pub struct WalletHistoryRequest {
    pub wallet_address: String,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct WalletPendingRequest {
    pub wallet_address: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenPriceRequest {
    pub tokens: Vec<String>, // Array of token symbols or mint addresses
}

#[derive(Debug, Deserialize)]
pub struct TokenSearchRequest {
    pub query: String,
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct WalletTokensRequest {
    pub wallet_address: String,
}

// NEW: Response types from Solana microservice
#[derive(Debug, Deserialize, Serialize)]
pub struct TransactionHistoryResponse {
    pub transactions: Vec<WalletTransaction>,
    pub total_count: Option<u32>,
    pub has_more: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WalletTransaction {
    pub signature: String,
    pub slot: u64,
    pub timestamp: Option<i64>,
    pub status: String, // "confirmed", "finalized", "failed"
    pub fee: Option<u64>,
    pub transaction_type: String, // "transfer", "swap", "program_interaction"
    pub amount: Option<f64>,
    pub token: Option<String>,
    pub from_address: Option<String>,
    pub to_address: Option<String>,
    pub memo: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PendingTransactionsResponse {
    pub pending_transactions: Vec<PendingTransaction>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PendingTransaction {
    pub signature: String,
    pub timestamp: i64,
    pub status: String,                           // "pending", "processing"
    pub estimated_confirmation_time: Option<u32>, // seconds
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenPriceResponse {
    pub prices: Vec<TokenPrice>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenPrice {
    pub symbol: String,
    pub mint_address: String,
    pub price_usd: f64,
    pub market_cap: Option<f64>,
    pub volume_24h: Option<f64>,
    pub price_change_24h: Option<f64>,
    pub last_updated: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenSearchResponse {
    pub tokens: Vec<TokenInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenInfo {
    pub symbol: String,
    pub name: String,
    pub mint_address: String,
    pub decimals: u8,
    pub logo_uri: Option<String>,
    pub verified: bool,
    pub daily_volume: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WalletTokensResponse {
    pub tokens: Vec<WalletToken>,
    pub total_value_usd: f64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WalletToken {
    pub mint_address: String,
    pub symbol: String,
    pub name: String,
    pub balance: f64,
    pub decimals: u8,
    pub price_usd: Option<f64>,
    pub value_usd: Option<f64>,
    pub logo_uri: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TransactionRequest {
    pub tx_type: String,        // "transfer", "swap", etc.
    pub from_token: String,     // "SOL", "USDC", etc.
    pub to_token: String,       // For swaps
    pub to_address: String,     // Recipient address
    pub amount: f64,            // Amount to transfer/swap
}


