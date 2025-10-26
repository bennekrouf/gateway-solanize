// src/main.rs - Updated with API0-centric architecture
use clap::{Parser, Subcommand};
use dotenv::dotenv;
use rocket::{catchers, routes};
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};
use std::collections::HashMap;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// mod api;
mod auth;
mod chat;
mod config;
mod db;
mod error;
mod payment;
mod solana;
mod types;

// use api::{auth, chat, wallet};
use auth::service::ChallengeStore;
use config::AppConfig;

#[derive(Parser)]
#[command(name = "gateway-solanize")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(alias = "server")]
    Serve,
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    dotenv().ok();
    let cli = Cli::parse();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Solana Gateway with API0 integration on port ",);

    // Load configuration and override port
    let mut config = AppConfig::load().expect("Failed to load configuration");

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
        .configure(
            rocket::Config::figment().merge((
                "port",
                std::env::var("ROCKET_PORT")
                    .expect("ROCKET_PORT environment variable is required")
                    .parse::<u16>()
                    .expect("ROCKET_PORT must be a valid port number"),
            )),
        )
        // Authentication endpoints
        .mount(
            "/api/v1/auth",
            routes![
                auth::handlers::challenge,
                auth::handlers::verify,
                auth::handlers::refresh
            ],
        )
        // MAIN INTERFACE: Chat with API0 integration
        .mount(
            "/api/v1/chat",
            routes![
                chat::handlers::create_session,
                chat::handlers::get_sessions,
                chat::handlers::send_message, // This handles ALL Solana operations via API0
                chat::handlers::get_messages,
                chat::handlers::chat_health,
                chat::handlers::delete_session,
                chat::handlers::list_models
            ],
        )
        // Clean wallet endpoints for UI context (read-only)
        // .mount(
        //     "/api/v1/wallet",
        //     routes![
        //         wallet::get_balance, // Direct call for UI balance display
        //         wallet::get_tokens,  // Direct call for UI portfolio display
        //         wallet::get_history, // Direct call for UI history display
        //         wallet::health_check,
        //     ],
        // )
        // Simplified payment endpoints (local transaction management only)
        .mount(
            "/api/v1/transactions",
            routes![
                payment::handlers::create_transaction, // For premium upgrades etc.
                payment::handlers::confirm_transaction, // For confirming payments
                payment::handlers::get_history,        // Local transaction history
                payment::handlers::health_check,
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
        .attach(cors);
    // .launch()
    // .await?;

    let rocket = _rocket;

    // Setup graceful shutdown
    let (tx, rx) = rocket::tokio::sync::oneshot::channel();

    rocket::tokio::spawn(async move {
        rocket::tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for ctrl+c");
        tracing::info!("Received shutdown signal");
        let _ = tx.send(());
    });

    let handle = rocket.launch();

    rocket::tokio::select! {
        result = handle => {
            result?;
        }
        _ = rx => {
            tracing::info!("Graceful shutdown initiated");
            // The rocket will shutdown when the select completes
        }
    }

    Ok(())
}

// NOTE: The following endpoints have been REMOVED and should be accessed via chat:
//
// REMOVED from /api/v1/transactions:
// - check_balance -> Chat: "What's my balance?"
// - get_wallet_tokens -> Chat: "Show my portfolio"
// - get_wallet_history -> Chat: "Show my transaction history"
// - get_pending_transactions -> Chat: "Any pending transactions?"
// - get_token_price -> Chat: "What's the price of SOL?"
// - search_tokens -> Chat: "Find RAY token"
// - get_trading_context -> Automatically included in chat context
//
// ALL SOLANA OPERATIONS NOW GO THROUGH:
// POST /api/v1/chat/sessions/{id}/messages
//
// This endpoint:
// 1. Analyzes user message with API0
// 2. Proposes actions with risk assessment
// 3. Requires user approval
// 4. Executes via Solana microservice
// 5. Returns prepared transactions for signing
// 6. Handles signed transaction submission
