use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "peer-ci", version, about = "Peer CI client")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print environment and exit.
    Doctor,

    /// Run a task inside a Firecracker microVM (stub).
    Run {
        /// Shell command to execute inside the VM.
        #[arg(long)]
        cmd: String,
    },
}
