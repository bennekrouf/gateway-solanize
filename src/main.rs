// src/main.rs
use clap::{Parser, Subcommand};
use dotenv::dotenv;
use rocket::{catchers, routes};
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};
use std::collections::HashMap;

mod auth;
mod chat;
mod config;
mod db;
mod error;
mod logging_macros;
mod payment;
mod solana;
mod types;

use auth::service::ChallengeStore;
use config::AppConfig;
use graflog::app_log;
use graflog::init_logging;
use graflog::LogOption;

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

    init_logging!("/var/log/solanize.log", "solanize", "gateway", &[
        LogOption::Debug,
        LogOption::RocketOff
    ]);

    app_log!(
        info,
        "Starting Solana Gateway (Claude + solanize-mcp) on port ",
    );

    // Load configuration and override port
    let mut config = AppConfig::load().expect("Failed to load configuration");

    // C3 — Fail-loud if JWT secret is the insecure default
    if config.auth.jwt_secret == "your-super-secret-jwt-key-change-in-production"
        || config.auth.jwt_secret.len() < 32
    {
        eprintln!(
            "FATAL: JWT secret is too short or is the default placeholder.\n\
             Set a strong secret (≥32 chars) in config.yaml or via the JWT_SECRET env var."
        );
        std::process::exit(1);
    }

    // Setup database
    let pool = db::setup_database(&config.database.url)
        .await
        .expect("Failed to setup database");

    // Initialize challenge store
    let challenge_store: ChallengeStore = rocket::tokio::sync::RwLock::new(HashMap::new());

    app_log!(info, "CORS config loaded:");
    app_log!(info, "  allowed_origins: {:?}", config.cors.allowed_origins);
    app_log!(info, "  allowed_methods: {:?}", config.cors.allowed_methods);
    app_log!(info, "  allowed_headers: {:?}", config.cors.allowed_headers);
    app_log!(
        info,
        "  allow_credentials: {}",
        config.cors.allow_credentials
    );

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
        // Chat interface — Claude calls solanize-mcp tools to handle all Solana operations
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
        app_log!(info, "Received shutdown signal");
        let _ = tx.send(());
    });

    let handle = rocket.launch();

    rocket::tokio::select! {
        result = handle => {
            result?;
        }
        _ = rx => {
            app_log!(info, "Graceful shutdown initiated");
            // The rocket will shutdown when the select completes
        }
    }

    Ok(())
}

// All Solana operations go through POST /api/v1/chat/sessions/{id}/messages
//
// Flow:
//  1. User message → Claude (Anthropic Messages API)
//  2. Claude calls solanize-mcp tools server-side (MCP connector beta)
//  3. For transfers/swaps: tool returns unsigned_transaction for frontend signing
//  4. User signs in their browser wallet and resends with signed_transaction field
//  5. Gateway submits signed tx to cli-solanize and returns the on-chain signature
