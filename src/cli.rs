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

    /// Download and cache a pinned Firecracker binary.
    InstallFirecracker {
        /// Firecracker version (e.g. 1.14.1 or v1.14.1)
        #[arg(long, default_value = "1.14.1")]
        version: String,

        /// Expected SHA256 of the release tgz (required if --version is not the pinned default)
        #[arg(long)]
        sha256: Option<String>,

        /// Target architecture (defaults to current machine)
        #[arg(long)]
        arch: Option<String>,

        /// Re-download even if already cached.
        #[arg(long)]
        force: bool,
    },

    /// Run a task inside a Firecracker microVM (stub).
    Run {
        /// Shell command to execute inside the VM.
        #[arg(long)]
        cmd: String,
    },
}
