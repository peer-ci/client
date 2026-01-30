use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncReadExt;

use crate::platform;

const PINNED_VERSION: &str = "1.14.1";
const PINNED_SHA256_X86_64: &str =
    "ea66dc1fbdb2473bbb95a1e822ae7884cd575a891a8f801258723258d36b7c7c";
const PINNED_SHA256_AARCH64: &str =
    "65a39256b9dd741e20c3a3fe5055cb38e5159049b5ede2015604951521000a04";

pub async fn doctor() -> Result<()> {
    // Stub: later we can validate KVM availability, Firecracker binary, API socket perms, etc.
    Ok(())
}

pub struct InstalledBinaries {
    pub firecracker: PathBuf,
    pub jailer: Option<PathBuf>,
}

pub async fn install_firecracker(
    version: String,
    sha256: Option<String>,
    arch: Option<String>,
    force: bool,
    install_jailer: bool,
) -> Result<InstalledBinaries> {
    let version = version.strip_prefix('v').unwrap_or(&version).to_string();

    let resolved_arch =
        platform::normalize_arch(arch.as_deref().unwrap_or(platform::current_arch()))?.to_string();

    let expected_sha256 = if version == PINNED_VERSION {
        match resolved_arch.as_str() {
            "x86_64" => PINNED_SHA256_X86_64.to_string(),
            "aarch64" => PINNED_SHA256_AARCH64.to_string(),
            _ => bail!("unsupported arch: {resolved_arch}"),
        }
    } else {
        sha256.ok_or_else(|| anyhow!("--sha256 is required when --version != {PINNED_VERSION}"))?
    };

    let cache_dir = cache_dir()?;
    let install_dir = cache_dir
        .join("firecracker")
        .join(format!("v{version}"))
        .join(&resolved_arch);
    let firecracker_path = install_dir.join("firecracker");
    let jailer_path = install_dir.join("jailer");

    let firecracker_exists = fs::try_exists(&firecracker_path).await.unwrap_or(false);
    let jailer_exists = fs::try_exists(&jailer_path).await.unwrap_or(false);

    if !force && firecracker_exists && (!install_jailer || jailer_exists) {
        return Ok(InstalledBinaries {
            firecracker: firecracker_path,
            jailer: if install_jailer {
                Some(jailer_path)
            } else {
                None
            },
        });
    }

    fs::create_dir_all(&install_dir)
        .await
        .with_context(|| format!("create cache dir: {}", install_dir.display()))?;

    let url = format!(
        "https://github.com/firecracker-microvm/firecracker/releases/download/v{version}/firecracker-v{version}-{resolved_arch}.tgz"
    );

    let tmp_tgz = install_dir.join("firecracker.tgz.tmp");
    download_to_path(&url, &tmp_tgz).await?;

    verify_sha256(&tmp_tgz, &expected_sha256).await?;

    extract_binary_from_tgz(
        &tmp_tgz,
        &firecracker_path,
        "firecracker",
        &version,
        &resolved_arch,
    )
    .await?;

    let jailer = if install_jailer {
        extract_binary_from_tgz(&tmp_tgz, &jailer_path, "jailer", &version, &resolved_arch).await?;
        Some(jailer_path)
    } else {
        None
    };

    let _ = fs::remove_file(&tmp_tgz).await;

    Ok(InstalledBinaries {
        firecracker: firecracker_path,
        jailer,
    })
}

pub async fn run_task(cmd: String) -> Result<()> {
    // Stub: later this will spin up a microVM and run the command inside it.
    tracing::info!(%cmd, "run requested");
    Ok(())
}

fn cache_dir() -> Result<PathBuf> {
    if let Ok(v) = std::env::var("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(v).join("peer-ci"));
    }

    let home = std::env::var("HOME").context("HOME not set (needed to resolve cache dir)")?;
    Ok(PathBuf::from(home).join(".cache").join("peer-ci"))
}

async fn download_to_path(url: &str, dest: &Path) -> Result<()> {
    // We intentionally use `curl` to avoid adding a full HTTP client dependency for now.
    let status = tokio::process::Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .await
        .context("failed to spawn curl")?;

    if !status.success() {
        bail!("download failed: {url}");
    }

    Ok(())
}

async fn verify_sha256(path: &Path, expected_hex: &str) -> Result<()> {
    let mut f = fs::File::open(path)
        .await
        .with_context(|| format!("open for sha256: {}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let actual = format!("{:x}", hasher.finalize());
    if actual != expected_hex {
        bail!(
            "sha256 mismatch for {}: expected {expected_hex}, got {actual}",
            path.display()
        );
    }

    Ok(())
}

async fn extract_binary_from_tgz(
    tgz: &Path,
    out_bin: &Path,
    binary: &str,
    version: &str,
    arch: &str,
) -> Result<()> {
    // Release tgz contains a top-level `release-vX.Y.Z-{arch}/{binary}-vX.Y.Z-{arch}`.
    // We extract into a temp dir and then rename to a stable name.
    let out_dir = out_bin
        .parent()
        .ok_or_else(|| anyhow!("invalid output path"))?;

    let tmp_dir = out_dir.join(format!(".tmp-extract-{binary}"));
    let _ = fs::remove_dir_all(&tmp_dir).await;
    fs::create_dir_all(&tmp_dir).await?;

    let wildcard = format!("*/{binary}*");

    let status = tokio::process::Command::new("tar")
        .args(["-xzf"])
        .arg(tgz)
        .args(["--wildcards", "--no-anchored"])
        .arg(&wildcard)
        .arg("--strip-components=1")
        .arg("-C")
        .arg(&tmp_dir)
        .status()
        .await
        .context("failed to spawn tar")?;

    if !status.success() {
        bail!("failed to extract {binary} from {}", tgz.display());
    }

    let expected = format!("{binary}-v{version}-{arch}");

    let mut entries = fs::read_dir(&tmp_dir).await?;
    let mut candidates: Vec<(String, PathBuf)> = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        if entry.metadata().await.map(|m| m.is_file()).unwrap_or(false) && name.starts_with(binary)
        {
            candidates.push((name, entry.path()));
        }
    }

    let src = if let Some((_, p)) = candidates.iter().find(|(n, _)| n == &expected) {
        p.clone()
    } else if let Some((_, p)) = candidates.iter().find(|(n, _)| n == binary) {
        p.clone()
    } else if candidates.len() == 1 {
        candidates[0].1.clone()
    } else {
        bail!(
            "unexpected extracted files for {binary}: {:?}",
            candidates.iter().map(|(n, _)| n).collect::<Vec<_>>()
        );
    };

    let _ = fs::remove_file(out_bin).await;
    fs::rename(&src, out_bin).await?;
    let _ = fs::remove_dir_all(&tmp_dir).await;

    // Ensure executable bit.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(out_bin).await?.permissions();
        perms.set_mode(perms.mode() | 0o111);
        fs::set_permissions(out_bin, perms).await?;
    }

    Ok(())
}
