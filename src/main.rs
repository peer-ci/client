mod cli;
mod firecracker;
mod platform;

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
        Command::InstallFirecracker {
            version,
            sha256,
            arch,
            force,
        } => {
            let path = firecracker::install_firecracker(version, sha256, arch, force).await?;
            println!("{}", path.display());
        }
        Command::Run { cmd } => {
            firecracker::run_task(cmd).await?;
        }
    }

    Ok(())
}
