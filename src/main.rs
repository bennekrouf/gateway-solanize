use rocket::{Build, Rocket, catchers, launch, routes};
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};
use sqlx::SqlitePool;
use std::collections::HashMap;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod chat;
mod config;
mod db;
mod error;
mod payment;
mod types;

use auth::service::ChallengeStore;
use config::AppConfig;
use error::AppResult;

#[launch]
async fn rocket() -> Rocket<Build> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Solana Gateway");

    // Load configuration
    let config = AppConfig::load().expect("Failed to load configuration");

    // Setup database
    let pool = db::setup_database(&config.database.url)
        .await
        .expect("Failed to setup database");

    // Initialize challenge store
    let challenge_store: ChallengeStore = rocket::tokio::sync::RwLock::new(HashMap::new());

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
        allowed_headers: AllowedHeaders::some(&config.cors.allowed_headers),
        allow_credentials: config.cors.allow_credentials,
        ..Default::default()
    }
    .to_cors()
    .expect("Failed to create CORS configuration");

    rocket::build()
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
                chat::handlers::get_messages
            ],
        )
        .mount(
            "/api/v1/transactions",
            routes![
                payment::handlers::create_transaction,
                payment::handlers::confirm_transaction,
                payment::handlers::get_history,
                payment::handlers::check_balance,
                payment::handlers::health_check
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
}

