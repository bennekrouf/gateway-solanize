use serde::Deserialize;
use std::env;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub cors: CorsConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub chat: ChatConfig,
    pub payment: PaymentConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub allow_credentials: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_expires_hours: u64,
    pub challenge_expires_minutes: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChatConfig {
    pub max_sessions_per_user: u32,
    pub max_messages_per_session: u32,
    pub ai_provider: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PaymentConfig {
    pub solana_service_url: String,
    pub premium_price_sol: f64,
    pub timeout_seconds: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

impl AppConfig {
    pub fn load() -> Result<Self, config::ConfigError> {
        let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| "config.yaml".to_string());

        config::Config::builder()
            .add_source(config::File::with_name(&config_path))
            .add_source(config::Environment::with_prefix("GATEWAY").separator("__"))
            .build()?
            .try_deserialize()
    }
}
