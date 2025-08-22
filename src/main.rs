use clap::{Parser, Subcommand};
use dotenv::dotenv;
use rocket::{catchers, routes};
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};
use std::collections::HashMap;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod chat;
mod config;
mod db;
mod error;
mod payment;
mod types;
mod api;
mod solana;

use auth::service::ChallengeStore;
use config::AppConfig;
use api::{auth, chat, wallet};

#[derive(Parser)]
#[command(name = "gateway-solanize")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(alias = "server")]
    Serve {
        #[arg(long, default_value_t = 5000)]
        port: u16,
    },
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    dotenv().ok();
    let cli = Cli::parse();

    let port = match cli.command {
        Some(Commands::Serve { port }) => port,
        None => 5000,
    };

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Solana Gateway on port {}", port);

    // Load configuration and override port
    let mut config = AppConfig::load().expect("Failed to load configuration");
    config.server.port = port;

    // Setup database
    let pool = db::setup_database(&config.database.url)
        .await
        .expect("Failed to setup database");

    // Initialize challenge store
    let challenge_store: ChallengeStore = rocket::tokio::sync::RwLock::new(HashMap::new());

    tracing::info!("CORS config loaded:");
    tracing::info!("  allowed_origins: {:?}", config.cors.allowed_origins);
    tracing::info!("  allowed_methods: {:?}", config.cors.allowed_methods);
    tracing::info!("  allowed_headers: {:?}", config.cors.allowed_headers);
    tracing::info!("  allow_credentials: {}", config.cors.allow_credentials);

    // Setup CORS
    let allowed_origins = AllowedOrigins::some_exact(&config.cors.allowed_origins);
    let allowed_headers: Vec<&str> = config
        .cors
        .allowed_headers
        .iter()
        .map(|s| s.as_str())
        .collect();

    tracing::info!("Processed headers for CORS: {:?}", allowed_headers);

    let cors = CorsOptions {
        allowed_origins,
        allowed_methods: config
            .cors
            .allowed_methods
            .iter()
            .map(|s| s.parse().expect("Invalid HTTP method"))
            .collect(),
        allowed_headers: AllowedHeaders::all(),
        allow_credentials: config.cors.allow_credentials,
        ..Default::default()
    }
    .to_cors()
    .expect("Failed to create CORS configuration");

    let _rocket = rocket::build()
        .configure(rocket::Config::figment().merge(("port", port)))
        .mount(
            "/api/v1/auth",
            routes![
                auth::handlers::challenge,
                auth::handlers::verify,
                auth::handlers::refresh
            ],
        )
        .mount(
            "/api/v1/chat",
            routes![
                chat::handlers::create_session,
                chat::handlers::get_sessions,
                chat::handlers::send_message,
                chat::handlers::get_messages,
                chat::handlers::chat_health,
                chat::handlers::delete_session,
                chat::handlers::list_models
            ],
        )
        .mount(
            "/api/v1/wallet",  // Clean frontend-facing wallet endpoints
            routes![
                wallet::get_balance,
                wallet::get_tokens,
                wallet::get_history,
                wallet::health_check,
            ],
        )
        .mount(
            "/api/v1/transactions",
            routes![
                // Keep only read-only endpoints for UI context:
                payment::handlers::check_balance,
                payment::handlers::get_wallet_tokens, // For portfolio display
                payment::handlers::health_check,
                payment::handlers::get_wallet_history,
                payment::handlers::get_history,
                // Remove: create_transaction, confirm_transaction, get_history
            ],
        )
        .register(
            "/",
            catchers![
                error::handlers::unauthorized,
                error::handlers::forbidden,
                error::handlers::not_found,
                error::handlers::internal_error
            ],
        )
        .manage(pool)
        .manage(config)
        .manage(challenge_store)
        .attach(cors)
        .launch()
        .await?;

    Ok(())
}
