use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncReadExt;

use crate::http_unix;
use crate::platform;

const PINNED_VERSION: &str = "1.14.1";
const PINNED_SHA256_X86_64: &str =
    "ea66dc1fbdb2473bbb95a1e822ae7884cd575a891a8f801258723258d36b7c7c";
const PINNED_SHA256_AARCH64: &str =
    "65a39256b9dd741e20c3a3fe5055cb38e5159049b5ede2015604951521000a04";

const HELLO_KERNEL_URL: &str =
    "https://s3.amazonaws.com/spec.ccfc.min/img/hello/kernel/hello-vmlinux.bin";
const HELLO_ROOTFS_URL: &str =
    "https://s3.amazonaws.com/spec.ccfc.min/img/hello/fsfiles/hello-rootfs.ext4";

const HELLO_KERNEL_SHA256: &str =
    "882fa465c43ab7d92e31bd4167da3ad6a82cb9230f9b0016176df597c6014cef";
const HELLO_ROOTFS_SHA256: &str =
    "786f0612582cadcee4c8ad46e30e4cc93dff9a3c0b4ede3f3c597b4c241dd547";

pub async fn doctor() -> Result<()> {
    println!("peer-ci doctor");

    let mut required_failures = 0usize;

    // REQUIRED: Linux
    if std::env::consts::OS == "linux" {
        pass("os", "linux");
    } else {
        fail(
            "os",
            &format!("expected linux, got {}", std::env::consts::OS),
        );
        required_failures += 1;
    }

    // REQUIRED: /dev/kvm exists and is readable+writable
    match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .await
    {
        Ok(_) => pass("kvm", "/dev/kvm is readable+writable"),
        Err(e) => {
            fail("kvm", &format!("/dev/kvm not accessible: {e}"));
            required_failures += 1;
        }
    }

    // OPTIONAL: architecture
    let arch = platform::current_arch();
    let normalized_arch = match platform::normalize_arch(arch) {
        Ok(a) => {
            pass("arch", a);
            a
        }
        Err(_) => {
            warn("arch", &format!("{arch} (expected x86_64 or aarch64)"));
            arch
        }
    };

    // OPTIONAL: tar/curl (installer uses them)
    check_tool("curl").await;
    check_tool("tar").await;

    // REQUIRED: firecracker + jailer present either in cache or on PATH
    let cache_dir = match cache_dir() {
        Ok(p) => Some(p),
        Err(e) => {
            warn("cache", &format!("unable to resolve cache dir: {e}"));
            None
        }
    };

    required_failures += check_binary("firecracker", cache_dir.as_deref(), normalized_arch).await;
    required_failures += check_binary("jailer", cache_dir.as_deref(), normalized_arch).await;

    // OPTIONAL: hello guest artifacts cached
    if let Some(cache_dir) = cache_dir.as_deref() {
        let guest_dir = hello_guest_dir(cache_dir, normalized_arch);
        let kernel = guest_dir.join("hello-vmlinux.bin");
        let rootfs = guest_dir.join("hello-rootfs.ext4");

        if fs::try_exists(&kernel).await.unwrap_or(false) {
            pass("guest-hello-kernel", &kernel.display().to_string());
        } else {
            warn("guest-hello-kernel", "not cached");
        }

        if fs::try_exists(&rootfs).await.unwrap_or(false) {
            pass("guest-hello-rootfs", &rootfs.display().to_string());
        } else {
            warn("guest-hello-rootfs", "not cached");
        }
    }

    if required_failures == 0 {
        println!("Result: OK");
        Ok(())
    } else {
        eprintln!("Result: FAILED ({required_failures} required check(s) failed)");
        bail!("doctor failed")
    }
}

pub struct InstalledBinaries {
    pub firecracker: PathBuf,
    pub jailer: Option<PathBuf>,
}

pub struct InstalledGuest {
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
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

pub async fn install_guest_hello(arch: Option<String>, force: bool) -> Result<InstalledGuest> {
    let arch_in = arch.unwrap_or_else(|| platform::current_arch().to_string());
    let resolved_arch = match platform::normalize_arch(&arch_in) {
        Ok(a) => a.to_string(),
        Err(_) => {
            tracing::warn!(arch = %arch_in, "unsupported arch; using as-is");
            arch_in
        }
    };

    let cache_dir = cache_dir()?;
    let install_dir = hello_guest_dir(&cache_dir, &resolved_arch);
    let kernel_path = install_dir.join("hello-vmlinux.bin");
    let rootfs_path = install_dir.join("hello-rootfs.ext4");

    let mut kernel_exists = fs::try_exists(&kernel_path).await.unwrap_or(false);
    let mut rootfs_exists = fs::try_exists(&rootfs_path).await.unwrap_or(false);

    if !force && kernel_exists {
        if let Err(e) = verify_sha256(&kernel_path, HELLO_KERNEL_SHA256).await {
            tracing::warn!(error = %e, "cached hello kernel sha256 mismatch; re-downloading");
            kernel_exists = false;
            let _ = fs::remove_file(&kernel_path).await;
        }
    }

    if !force && rootfs_exists {
        if let Err(e) = verify_sha256(&rootfs_path, HELLO_ROOTFS_SHA256).await {
            tracing::warn!(error = %e, "cached hello rootfs sha256 mismatch; re-downloading");
            rootfs_exists = false;
            let _ = fs::remove_file(&rootfs_path).await;
        }
    }

    if !force && kernel_exists && rootfs_exists {
        return Ok(InstalledGuest {
            kernel: kernel_path,
            rootfs: rootfs_path,
        });
    }

    fs::create_dir_all(&install_dir)
        .await
        .with_context(|| format!("create cache dir: {}", install_dir.display()))?;

    if force || !kernel_exists {
        let tmp = install_dir.join("hello-vmlinux.bin.tmp");
        download_to_path(HELLO_KERNEL_URL, &tmp).await?;
        if let Err(e) = verify_sha256(&tmp, HELLO_KERNEL_SHA256).await {
            let _ = fs::remove_file(&tmp).await;
            return Err(e);
        }
        let _ = fs::remove_file(&kernel_path).await;
        fs::rename(&tmp, &kernel_path).await?;
    }

    if force || !rootfs_exists {
        let tmp = install_dir.join("hello-rootfs.ext4.tmp");
        download_to_path(HELLO_ROOTFS_URL, &tmp).await?;
        if let Err(e) = verify_sha256(&tmp, HELLO_ROOTFS_SHA256).await {
            let _ = fs::remove_file(&tmp).await;
            return Err(e);
        }
        let _ = fs::remove_file(&rootfs_path).await;
        fs::rename(&tmp, &rootfs_path).await?;
    }

    Ok(InstalledGuest {
        kernel: kernel_path,
        rootfs: rootfs_path,
    })
}

pub async fn run_task(cmd: String) -> Result<()> {
    // Currently boots the cached hello guest and streams the serial console.
    // `cmd` is accepted for CLI compatibility but not used yet.
    let _ = cmd;

    // Fail fast with a clear message (we run unprivileged).
    match fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").await {
        Ok(_) => {}
        Err(e) => {
            bail!("/dev/kvm not accessible ({e}); try `peer-ci doctor` and ensure your user has permission (often via the kvm group)");
        }
    }

    let arch = platform::normalize_arch(platform::current_arch())
        .unwrap_or_else(|_| platform::current_arch());
    let cache_dir = cache_dir()?;

    let firecracker = find_cached_bin(&cache_dir, arch, "firecracker")
        .await
        .ok_or_else(|| anyhow!("firecracker not installed; run `peer-ci install-firecracker`"))?;
    let jailer = find_cached_bin(&cache_dir, arch, "jailer")
        .await
        .ok_or_else(|| anyhow!("jailer not installed; run `peer-ci install-firecracker`"))?;

    let guest_dir = hello_guest_dir(&cache_dir, arch);
    let kernel_src = guest_dir.join("hello-vmlinux.bin");
    let rootfs_src = guest_dir.join("hello-rootfs.ext4");

    if !fs::try_exists(&kernel_src).await.unwrap_or(false)
        || !fs::try_exists(&rootfs_src).await.unwrap_or(false)
    {
        bail!("hello guest not installed; run `peer-ci install-firecracker` (without --no-guest)");
    }

    let id = format!("{}-{}", std::process::id(), now_millis());
    let chroot_base = default_chroot_base();

    let jail_root = chroot_base.join(&id).join("root");
    let _ = fs::remove_dir_all(chroot_base.join(&id)).await;
    fs::create_dir_all(&jail_root).await.with_context(|| {
        format!("create jail root: {}", jail_root.display())
    })?;

    let kernel_jail = jail_root.join("hello-vmlinux.bin");
    let rootfs_jail = jail_root.join("hello-rootfs.ext4");

    link_or_copy(&kernel_src, &kernel_jail).await?;
    link_or_copy(&rootfs_src, &rootfs_jail).await?;

    // Firecracker socket will be created inside chroot at /run/firecracker.socket.
    let run_dir = jail_root.join("run");
    fs::create_dir_all(&run_dir).await?;
    let api_sock_in_jail = "/run/firecracker.socket";
    let api_sock_host = run_dir.join("firecracker.socket");

    let uid = nix_uid();
    let gid = nix_gid();

    let mut child = tokio::process::Command::new(&jailer)
        .arg("--id")
        .arg(&id)
        .arg("--exec-file")
        .arg(&firecracker)
        .arg("--uid")
        .arg(uid.to_string())
        .arg("--gid")
        .arg(gid.to_string())
        .arg("--chroot-base-dir")
        .arg(&chroot_base)
        .arg("--")
        .arg("--api-sock")
        .arg(api_sock_in_jail)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| "spawn jailer")?;

    // Pump jailer/firecracker output to our stdout/stderr.
    if let Some(out) = child.stdout.take() {
        tokio::spawn(async move {
            let mut r = tokio::io::BufReader::new(out);
            let mut w = tokio::io::stdout();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(async move {
            let mut r = tokio::io::BufReader::new(err);
            let mut w = tokio::io::stderr();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
    }

    let jailer_pid = child.id().unwrap_or(0) as i32;
    let cleanup_dir = chroot_base.join(&id);

    let cleanup = |pid: i32, dir: PathBuf| async move {
        if pid != 0 {
            let _ = tokio::process::Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .status()
                .await;
        }
        let _ = fs::remove_dir_all(&dir).await;
    };

    // Wait for API socket (unprivileged path/permissions issues will surface here).
    if let Err(e) = wait_for_socket_or_exit(&api_sock_host, &mut child).await {
        cleanup(jailer_pid, cleanup_dir.clone()).await;
        return Err(e);
    }

    // Configure VM via Firecracker API.
    if let Err(e) = async {
        http_unix::put_json(
            &api_sock_host,
            "/machine-config",
            r#"{"vcpu_count":1,"mem_size_mib":256,"ht_enabled":false}"#,
        )
        .await?;
        http_unix::put_json(
            &api_sock_host,
            "/boot-source",
            "{\"kernel_image_path\":\"/hello-vmlinux.bin\",\"boot_args\":\"console=ttyS0 reboot=k panic=1\"}",
        )
        .await?;
        http_unix::put_json(
            &api_sock_host,
            "/drives/rootfs",
            "{\"drive_id\":\"rootfs\",\"path_on_host\":\"/hello-rootfs.ext4\",\"is_root_device\":true,\"is_read_only\":false}",
        )
        .await?;
        http_unix::put_json(&api_sock_host, "/actions", r#"{"action_type":"InstanceStart"}"#).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await
    {
        cleanup(jailer_pid, cleanup_dir.clone()).await;
        return Err(e);
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            cleanup(jailer_pid, cleanup_dir).await;
            Ok(())
        }
        status = child.wait() => {
            let _ = fs::remove_dir_all(&cleanup_dir).await;
            let status = status?;
            if status.success() {
                Ok(())
            } else {
                bail!("jailer exited with status: {status}")
            }
        }
    }
}

fn default_chroot_base() -> PathBuf {
    if let Ok(v) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(v).join("peer-ci").join("jailer");
    }
    PathBuf::from("/tmp").join("peer-ci").join("jailer")
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(unix)]
unsafe extern "C" {
    fn getuid() -> u32;
    fn getgid() -> u32;
}

fn nix_uid() -> u32 {
    #[cfg(unix)]
    unsafe {
        getuid()
    }

    #[cfg(not(unix))]
    {
        0
    }
}

fn nix_gid() -> u32 {
    #[cfg(unix)]
    unsafe {
        getgid()
    }

    #[cfg(not(unix))]
    {
        0
    }
}

async fn link_or_copy(src: &Path, dest: &Path) -> Result<()> {
    let _ = fs::remove_file(dest).await;
    match fs::hard_link(src, dest).await {
        Ok(_) => Ok(()),
        Err(_) => {
            fs::copy(src, dest)
                .await
                .with_context(|| format!("copy {} -> {}", src.display(), dest.display()))?;
            Ok(())
        }
    }
}

async fn find_cached_bin(cache_dir: &Path, arch: &str, bin: &str) -> Option<PathBuf> {
    let root = cache_dir.join("firecracker");
    let mut best: Option<(String, PathBuf)> = None;

    let mut versions = fs::read_dir(&root).await.ok()?;
    while let Ok(Some(entry)) = versions.next_entry().await {
        let ver = entry.file_name().to_string_lossy().to_string();
        let candidate = entry.path().join(arch).join(bin);
        if fs::try_exists(&candidate).await.unwrap_or(false) && is_executable(&candidate) {
            match &best {
                Some((best_ver, _)) if best_ver >= &ver => {}
                _ => best = Some((ver, candidate)),
            }
        }
    }

    best.map(|(_, p)| p)
}

async fn wait_for_socket_or_exit(sock: &Path, child: &mut tokio::process::Child) -> Result<()> {
    use tokio::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if fs::try_exists(sock).await.unwrap_or(false) {
            return Ok(());
        }

        if let Some(status) = child.try_wait()? {
            bail!("jailer exited before creating API socket: {status}");
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    bail!(
        "Firecracker API socket not created at {}. This is often a permissions issue (jailer/chroot or /dev/kvm). Try `peer-ci doctor` and ensure you can access /dev/kvm; also ensure the jailer binary can run unprivileged.",
        sock.display()
    )
}

fn cache_dir() -> Result<PathBuf> {
    if let Ok(v) = std::env::var("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(v).join("peer-ci"));
    }

    let home = std::env::var("HOME").context("HOME not set (needed to resolve cache dir)")?;
    Ok(PathBuf::from(home).join(".cache").join("peer-ci"))
}

fn hello_guest_dir(cache_dir: &Path, arch: &str) -> PathBuf {
    cache_dir.join("guest").join("hello").join(arch)
}

fn pass(check: &str, msg: &str) {
    println!("PASS {check}: {msg}");
}

fn warn(check: &str, msg: &str) {
    println!("WARN {check}: {msg}");
}

fn fail(check: &str, msg: &str) {
    eprintln!("FAIL {check}: {msg}");
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }

    #[cfg(not(unix))]
    {
        true
    }
}

fn which_all(cmd: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();

    let Some(path) = std::env::var_os("PATH") else {
        return out;
    };

    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(cmd);
        if is_executable(&candidate) && !out.contains(&candidate) {
            out.push(candidate);
        }
    }

    out
}

async fn version_line(bin: &Path) -> Option<String> {
    let out = tokio::process::Command::new(bin)
        .arg("--version")
        .output()
        .await
        .ok()?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut s = stdout.lines().chain(stderr.lines()).map(str::trim);
    s.find(|l| !l.is_empty()).map(|l| l.to_string())
}

async fn check_tool(cmd: &str) {
    let paths = which_all(cmd);
    if paths.is_empty() {
        warn(cmd, "not found on PATH");
        return;
    }

    for p in paths {
        let ver = version_line(&p).await;
        if let Some(ver) = ver {
            pass(cmd, &format!("{} ({ver})", p.display()));
        } else {
            pass(cmd, &p.display().to_string());
        }
    }
}

async fn check_binary(bin: &str, cache_dir: Option<&Path>, arch: &str) -> usize {
    let mut found = Vec::new();

    if let Some(cache_dir) = cache_dir {
        let root = cache_dir.join("firecracker");
        if let Ok(mut versions) = fs::read_dir(&root).await {
            while let Ok(Some(entry)) = versions.next_entry().await {
                let version_dir = entry.path();
                let candidate = version_dir.join(arch).join(bin);
                if fs::try_exists(&candidate).await.unwrap_or(false)
                    && is_executable(&candidate)
                    && !found
                        .iter()
                        .any(|(_, p): &(String, PathBuf)| p == &candidate)
                {
                    found.push(("cache".to_string(), candidate));
                }
            }
        }
    }

    for p in which_all(bin) {
        found.push(("PATH".to_string(), p));
    }

    if found.is_empty() {
        fail(bin, "not found in cache or on PATH");
        return 1;
    }

    for (src, p) in found {
        let ver = version_line(&p).await;
        let msg = if let Some(ver) = ver {
            format!("{src}: {} ({ver})", p.display())
        } else {
            format!("{src}: {}", p.display())
        };
        pass(bin, &msg);
    }

    0
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
