pub mod admin;
pub mod api;
pub mod crypto;
pub mod mqtt;
pub mod store;
pub mod sync;
pub mod writer;

use axum::{routing::get, Router};
use clap::Parser;
use std::env;
use std::process;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Command>,
}

#[derive(Parser, Debug)]
enum Command {
    Healthcheck,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    match args.cmd {
        Some(Command::Healthcheck) => {
            println!("ok");
            return Ok(());
        }
        None => {}
    }

    if env::var("MASTER_KEY").is_err() {
        eprintln!("MASTER_KEY not set");
        process::exit(1);
    }

    let bind_addr = env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8000".to_string());

    let app = app();
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    println!("Listening on {}", bind_addr);
    axum::serve(listener, app).await?;

    Ok(())
}

pub fn app() -> Router {
    Router::new().route("/healthz", get(|| async { "ok" }))
}
