//! Moonveil (`moonveil`) binary entrypoint.

#[tokio::main]
async fn main() {
    moonveil::cli::run_cli().await;
}
