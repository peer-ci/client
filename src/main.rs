mod cli;
mod firecracker;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Doctor => {
            firecracker::doctor().await?;
            println!("ok");
        }
        Command::Run { cmd } => {
            firecracker::run_task(cmd).await?;
        }
    }

    Ok(())
}
