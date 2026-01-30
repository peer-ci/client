use anyhow::{Context, Result, bail};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub async fn put_json(sock: &Path, path: &str, json_body: &str) -> Result<u16> {
    let mut stream = UnixStream::connect(sock)
        .await
        .with_context(|| format!("connect unix socket: {}", sock.display()))?;

    let req = format!(
        "PUT {path} HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        json_body.as_bytes().len(),
        json_body
    );

    stream.write_all(req.as_bytes()).await?;
    stream.shutdown().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    let raw = String::from_utf8_lossy(&buf);
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .unwrap_or((raw.as_ref(), ""));

    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    if !(200..300).contains(&status) {
        bail!("http PUT {path} failed: status {status}; response: {}", raw.trim());
    }

    let _ = body;
    Ok(status)
}
