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

// Keep the rest of your types unchanged...

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

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub user_message: Message,
    pub ai_message: Message,
}

// Ollama API types
// #[derive(Debug, Serialize)]
// pub struct OllamaRequest {
//     pub model: String,
//     pub messages: Vec<OllamaMessage>,
//     pub stream: bool,
// }
//
// #[derive(Debug, Serialize)]
// pub struct OllamaMessage {
//     pub role: String, // "user", "assistant", "system"
//     pub content: String,
// }

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
