use anyhow::Result;

pub async fn doctor() -> Result<()> {
    // Stub: later we can validate KVM availability, Firecracker binary, API socket perms, etc.
    Ok(())
}

pub async fn run_task(cmd: String) -> Result<()> {
    // Stub: later this will spin up a microVM and run the command inside it.
    tracing::info!(%cmd, "run requested");
    Ok(())
}
