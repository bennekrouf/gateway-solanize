use chrono::{Duration, Utc};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::{Rng, distributions::Alphanumeric};
use rocket::{State, tokio::sync::RwLock};
use sqlx::SqlitePool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    config::AppConfig,
    error::{AppError, AppResult},
    types::{AuthResponse, Challenge, Claims, User},
};

pub type ChallengeStore = RwLock<HashMap<String, Challenge>>;

pub struct AuthService<'a> {
    config: &'a AppConfig,
}

impl<'a> AuthService<'a> {
    pub fn new(config: &'a AppConfig) -> Self {
        Self { config }
    }

    pub async fn generate_challenge(
        &self,
        wallet_address: &str,
        store: &State<ChallengeStore>,
    ) -> AppResult<Challenge> {
        // Validate wallet address format first
        self.validate_wallet_address(wallet_address)?;

        let message: String = rand::rngs::ThreadRng::default()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let challenge_text = format!(
            "Please sign this message to authenticate with Solana Gateway:\n\n{}\n\nWallet: {}\nTime: {}",
            message,
            wallet_address,
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );

        let challenge = Challenge {
            message: challenge_text.clone(),
            expires_at: Utc::now()
                + Duration::minutes(self.config.auth.challenge_expires_minutes as i64),
        };

        let mut challenges = store.write().await;
        challenges.insert(challenge_text, challenge.clone());

        // Clean expired challenges
        let now = Utc::now();
        challenges.retain(|_, v| v.expires_at > now);

        app_log!(info, "Generated challenge for wallet: {}", wallet_address);
        Ok(challenge)
    }

    pub async fn verify_signature(
        &self,
        wallet_address: &str,
        signature: &str,
        challenge_message: &str,
        pool: &SqlitePool,
        store: &State<ChallengeStore>,
    ) -> AppResult<AuthResponse> {
        // Validate challenge exists and not expired
        let challenges = store.read().await;
        let challenge = challenges
            .get(challenge_message)
            .ok_or_else(|| AppError::Auth("Invalid or expired challenge".to_string()))?;

        if challenge.expires_at < Utc::now() {
            return Err(AppError::Auth("Challenge expired".to_string()));
        }

        // Verify Solana signature
        self.verify_solana_signature(wallet_address, signature, challenge_message)?;

        // Remove used challenge
        drop(challenges);
        let mut challenges = store.write().await;
        challenges.remove(challenge_message);

        // Get or create user
        let user = self.get_or_create_user(wallet_address, pool).await?;

        // Generate JWT
        let jwt = self.generate_jwt(wallet_address, &user.id.to_string())?;

        app_log!(info, "Successful authentication for wallet: {}", wallet_address);
        Ok(AuthResponse { jwt, user })
    }

    fn validate_wallet_address(&self, wallet_address: &str) -> AppResult<()> {
        // Basic validation: Solana addresses are base58 encoded and 32 bytes (44 chars)
        if wallet_address.len() < 32 || wallet_address.len() > 44 {
            return Err(AppError::Auth("Invalid wallet address length".to_string()));
        }

        // Validate base58 encoding
        bs58::decode(wallet_address)
            .into_vec()
            .map_err(|_| AppError::Auth("Invalid base58 wallet address".to_string()))?;

        Ok(())
    }

    fn verify_solana_signature(
        &self,
        wallet_address: &str,
        signature_b58: &str,
        message: &str,
    ) -> AppResult<()> {
        // Decode base58 public key
        let pubkey_bytes = bs58::decode(wallet_address)
            .into_vec()
            .map_err(|_| AppError::Auth("Invalid wallet address format".to_string()))?;

        if pubkey_bytes.len() != 32 {
            return Err(AppError::Auth("Invalid public key length".to_string()));
        }

        // Decode base58 signature
        let signature_bytes = bs58::decode(signature_b58)
            .into_vec()
            .map_err(|_| AppError::Auth("Invalid signature format".to_string()))?;

        if signature_bytes.len() != 64 {
            return Err(AppError::Auth("Invalid signature length".to_string()));
        }

        // Convert to ed25519 types for verification
        let mut pubkey_array = [0u8; 32];
        pubkey_array.copy_from_slice(&pubkey_bytes);

        let mut signature_array = [0u8; 64];
        signature_array.copy_from_slice(&signature_bytes);

        let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
            .map_err(|_| AppError::Auth("Invalid public key".to_string()))?;

        let ed25519_signature = Ed25519Signature::from_bytes(&signature_array);

        // Verify the signature against the message
        verifying_key
            .verify(message.as_bytes(), &ed25519_signature)
            .map_err(|e| {
                app_log!(warn, "Signature verification failed: {:?}", e);
                AppError::Auth("Signature verification failed".to_string())
            })?;

        app_log!(debug, 
            "Signature verified successfully for wallet: {}",
            wallet_address
        );
        Ok(())
    }

    async fn get_or_create_user(&self, wallet_address: &str, pool: &SqlitePool) -> AppResult<User> {
        // Try to get existing user
        if let Ok(user) = sqlx::query_as::<_, User>(
            "SELECT id, wallet_address, created_at, is_premium FROM users WHERE wallet_address = ?",
        )
        .bind(wallet_address)
        .fetch_one(pool)
        .await
        {
            app_log!(debug, "Found existing user: {}", user.id);
            return Ok(user);
        }

        // Create new user with INSERT OR IGNORE to handle race conditions
        let user_id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            "INSERT OR IGNORE INTO users (id, wallet_address, created_at, is_premium) VALUES (?, ?, ?, ?)"
        )
        .bind(user_id.to_string())
        .bind(wallet_address)
        .bind(now.to_rfc3339())
        .bind(false)
        .execute(pool)
        .await?;

        // Fetch the user (either just created or existing from race condition)
        let user = sqlx::query_as::<_, User>(
            "SELECT id, wallet_address, created_at, is_premium FROM users WHERE wallet_address = ?",
        )
        .bind(wallet_address)
        .fetch_one(pool)
        .await?;

        app_log!(info, "User ready: {} for wallet: {}", user.id, wallet_address);
        Ok(user)
    }

    pub fn generate_jwt(&self, wallet_address: &str, user_id: &str) -> AppResult<String> {
        let now = chrono::Utc::now();
        let expires = now + Duration::hours(self.config.auth.jwt_expires_hours as i64);

        let claims = Claims {
            sub: wallet_address.to_string(),
            user_id: user_id.to_string(),
            iat: now.timestamp() as usize,
            exp: expires.timestamp() as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.auth.jwt_secret.as_bytes()),
        )
        .map_err(|e| AppError::Internal(format!("Failed to generate JWT: {}", e)))
    }

    pub fn verify_jwt(&self, token: &str) -> AppResult<Claims> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.auth.jwt_secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .map(|data| data.claims)
        .map_err(|e| {
            app_log!(warn, "JWT verification failed: {:?}", e);
            AppError::Auth("Invalid or expired token".to_string())
        })
    }
}
