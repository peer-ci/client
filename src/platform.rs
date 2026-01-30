use anyhow::{Result, bail};

pub fn normalize_arch(arch: &str) -> Result<&'static str> {
    match arch {
        "x86_64" | "amd64" => Ok("x86_64"),
        "aarch64" | "arm64" => Ok("aarch64"),
        other => bail!("unsupported arch: {other}"),
    }
}

pub fn current_arch() -> &'static str {
    std::env::consts::ARCH
}
