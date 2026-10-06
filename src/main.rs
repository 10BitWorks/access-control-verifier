use access_control_verifier::api::{AppState, NoopSink};
use access_control_verifier::app;
use access_control_verifier::crypto::Key;
use access_control_verifier::store::Store;
use clap::Parser;
use std::env;
use std::process;
use std::sync::{Arc, Mutex};

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

    let master_key_hex = env::var("MASTER_KEY").unwrap_or_else(|_| {
        eprintln!("MASTER_KEY not set");
        process::exit(1);
    });

    let db_path = env::var("DB_PATH").unwrap_or_else(|_| "access.db".to_string());
    let store = Store::open(&db_path).unwrap_or_else(|e| {
        eprintln!("Failed to open database {}: {}", db_path, e);
        process::exit(1);
    });

    let state = AppState {
        store: Arc::new(Mutex::new(store)),
        master: Key::from_hex(&master_key_hex).unwrap_or_else(|_| {
            eprintln!("Invalid MASTER_KEY hex");
            process::exit(1);
        }),
        secret: env::var("EMQX_SECRET").unwrap_or_default(),
        sink: Arc::new(NoopSink), // To be replaced when MQTT is hooked up
    };

    let bind_addr = env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8000".to_string());

    let app = app(state);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    println!("Listening on {}", bind_addr);
    axum::serve(listener, app).await?;

    Ok(())
}
