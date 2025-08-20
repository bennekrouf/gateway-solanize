pub mod auth;
pub mod chat;
pub mod config;
pub mod db;
pub mod error;
pub mod payment;
pub mod types;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_loading() {
        // Test that config structure is valid
        let config_str = r#"
server:
  host: "127.0.0.1"
  port: 5000
  workers: 4
cors:
  allowed_origins: ["http://localhost:3000"]
  allowed_methods: ["GET", "POST"]
  allowed_headers: ["Content-Type", "Authorization"]
  allow_credentials: true
database:
  url: "sqlite://test.db"
  max_connections: 10
auth:
  jwt_secret: "test-secret"
  jwt_expires_hours: 24
  challenge_expires_minutes: 5
chat:
  max_sessions_per_user: 100
  max_messages_per_session: 1000
  ai_provider: "ollama"
  ollama_url: "http://localhost:11434"
  ollama_model: "llama3.1"
  ollama_timeout_seconds: 30
payment:
  solana_network: "devnet"
  premium_price_sol: 0.1
logging:
  level: "info"
  format: "json"
        "#;

        let config: config::AppConfig =
            serde_yaml::from_str(config_str).expect("Invalid config structure");
        assert_eq!(config.server.port, 5000);
        assert_eq!(config.cors.allow_credentials, true);
        assert_eq!(config.auth.jwt_expires_hours, 24);
    }

    #[test]
    fn test_error_types() {
        use error::AppError;

        let auth_error = AppError::Auth("test".to_string());
        assert!(auth_error.to_string().contains("Authentication error"));

        let validation_error = AppError::Validation("test".to_string());
        assert!(validation_error.to_string().contains("Validation error"));
    }
}
