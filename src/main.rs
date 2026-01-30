mod cli;
mod firecracker;
mod platform;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> Result<ExitCode> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Doctor => {
            if firecracker::doctor().await.is_err() {
                Ok(ExitCode::FAILURE)
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }
        cmd => {
            run_command(cmd).await?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn run_command(cmd: Command) -> Result<()> {
    match cmd {
        Command::InstallFirecracker {
            version,
            sha256,
            arch,
            force,
            no_jailer,
            no_guest,
        } => {
            let fc =
                firecracker::install_firecracker(version, sha256, arch.clone(), force, !no_jailer)
                    .await?;
            println!("{}", fc.firecracker.display());
            if let Some(jailer) = fc.jailer {
                println!("{}", jailer.display());
            }

            if !no_guest {
                let guest = firecracker::install_guest_hello(arch, force).await?;
                println!("{}", guest.kernel.display());
                println!("{}", guest.rootfs.display());
            }
        }
        Command::Run { cmd } => {
            firecracker::run_task(cmd).await?;
        }
        Command::Doctor => unreachable!(),
    }

    Ok(())
}
