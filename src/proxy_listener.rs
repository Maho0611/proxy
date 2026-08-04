//! Proxy pool listener — exposes standard SOCKS5 / HTTP proxy endpoints.
//!
//! Each incoming connection is authenticated via fixed credentials,
//! with optional per-connection filters encoded in the username suffix.
//!
//! ## Filter encoding in username
//!
//! | Username | Filters |
//! |---|---|
//! | `myuser` | None (random proxy) |
//! | `myuser-country-US` | country=US |
//! | `myuser-country-US-residential` | country=US, residential |
//! | `myuser-chatgpt-google` | chatgpt, google |
//!
//! ## Protocol auto-detection
//!
//! First byte `0x05` → SOCKS5; ASCII → HTTP proxy.

use crate::bindings::BindingUseGuard;
use crate::pool::manager::ProxyFilter;
use crate::AppState;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Spawn a TCP listener task for each configured proxy listener.
pub fn start_proxy_listeners(state: Arc<AppState>) {
    for cfg in &state.config.proxy_listener {
        let state = state.clone();
        let cfg = Arc::new(cfg.clone());
        tokio::spawn(async move {
            if let Err(e) = run_listener(state, cfg).await {
                tracing::error!("Proxy listener failed: {e}");
            }
        });
    }
}

async fn run_listener(
    state: Arc<AppState>,
    cfg: Arc<crate::config::ProxyListenerConfig>,
) -> Result<(), String> {
    let listener = TcpListener::bind(&cfg.listen)
        .await
        .map_err(|e| format!("Failed to bind proxy listener {}: {e}", cfg.listen))?;

    tracing::info!(
        "Proxy listener '{}' started on {} (SOCKS5+HTTP, user={})",
        cfg.name,
        cfg.listen,
        cfg.username
    );

    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("Accept failed: {e}"))?;

        let state = state.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, state, cfg).await {
                tracing::debug!("Proxy listener connection from {peer} ended: {e}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Protocol detection
// ---------------------------------------------------------------------------

async fn handle_connection(
    stream: TcpStream,
    state: Arc<AppState>,
    cfg: Arc<crate::config::ProxyListenerConfig>,
) -> Result<(), String> {
    let mut peek = [0u8; 1];
    stream
        .peek(&mut peek)
        .await
        .map_err(|e| format!("peek: {e}"))?;

    match peek[0] {
        0x05 => handle_socks5(stream, state, cfg).await,
        _ => handle_http_proxy(stream, state, cfg).await,
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 server (RFC 1928 + RFC 1929)
// ---------------------------------------------------------------------------

async fn handle_socks5(
    mut stream: TcpStream,
    state: Arc<AppState>,
    cfg: Arc<crate::config::ProxyListenerConfig>,
) -> Result<(), String> {
    // --- Method negotiation ---
    let mut hdr = [0u8; 2];
    read_exact(&mut stream, &mut hdr).await?;
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    read_exact(&mut stream, &mut methods).await?;

    if !methods.contains(&0x02) {
        stream.write_all(&[0x05, 0xFF]).await.ok();
        return Err("Client doesn't support username/password auth".into());
    }
    write_all(&mut stream, &[0x05, 0x02]).await?;

    // --- Username/password auth (RFC 1929) ---
    let mut auth_ver = [0u8; 1];
    read_exact(&mut stream, &mut auth_ver).await?;

    let mut ulen = [0u8; 1];
    read_exact(&mut stream, &mut ulen).await?;
    let mut uname = vec![0u8; ulen[0] as usize];
    read_exact(&mut stream, &mut uname).await?;

    let mut plen = [0u8; 1];
    read_exact(&mut stream, &mut plen).await?;
    let mut passwd = vec![0u8; plen[0] as usize];
    read_exact(&mut stream, &mut passwd).await?;

    let username = String::from_utf8_lossy(&uname).to_string();
    let password = String::from_utf8_lossy(&passwd).to_string();

    let auth = match authenticate_and_parse(&state, &cfg, &username, &password) {
        Some(auth) => auth,
        None => {
            stream.write_all(&[0x01, 0x01]).await.ok();
            return Err("SOCKS5 auth failed".into());
        }
    };
    mark_account_used(&state, auth.account_id.as_deref());
    let filter = auth.filter;
    write_all(&mut stream, &[0x01, 0x00]).await?;

    // --- CONNECT request ---
    let mut req = [0u8; 4];
    read_exact(&mut stream, &mut req).await?;

    if req[1] != 0x01 {
        // Only CONNECT supported
        write_all(&mut stream, &[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err("Only CONNECT supported".into());
    }

    let (target_host, target_port) = read_socks5_address(&mut stream, req[3]).await?;

    // --- Connect through proxy pool ---
    match connect_through_pool(&state, &filter, &target_host, target_port).await {
        Ok((mut upstream, _guard)) => {
            write_all(&mut stream, &[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            tokio::io::copy_bidirectional(&mut stream, &mut upstream)
                .await
                .ok();
            // _guard dropped here — releases binding usage
            Ok(())
        }
        Err(e) => {
            write_all(&mut stream, &[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            Err(format!(
                "Connect to {target_host}:{target_port} failed: {e}"
            ))
        }
    }
}

async fn read_socks5_address(stream: &mut TcpStream, atyp: u8) -> Result<(String, u16), String> {
    match atyp {
        0x01 => {
            // IPv4
            let mut buf = [0u8; 6]; // 4 addr + 2 port
            read_exact(stream, &mut buf).await?;
            let host = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok((host, port))
        }
        0x03 => {
            // Domain
            let mut len = [0u8; 1];
            read_exact(stream, &mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            read_exact(stream, &mut domain).await?;
            let mut port_buf = [0u8; 2];
            read_exact(stream, &mut port_buf).await?;
            Ok((
                String::from_utf8_lossy(&domain).to_string(),
                u16::from_be_bytes(port_buf),
            ))
        }
        0x04 => {
            // IPv6
            let mut buf = [0u8; 18]; // 16 addr + 2 port
            read_exact(stream, &mut buf).await?;
            let segs: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([buf[i * 2], buf[i * 2 + 1]])))
                .collect();
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok((format!("[{}]", segs.join(":")), port))
        }
        _ => Err("Unsupported SOCKS5 address type".into()),
    }
}

// ---------------------------------------------------------------------------
// HTTP proxy server (CONNECT + plain HTTP)
// ---------------------------------------------------------------------------

async fn handle_http_proxy(
    mut stream: TcpStream,
    state: Arc<AppState>,
    cfg: Arc<crate::config::ProxyListenerConfig>,
) -> Result<(), String> {
    // Read headers until \r\n\r\n (max 8 KiB)
    let mut buf = Vec::with_capacity(4096);
    let header_end;
    loop {
        let mut tmp = [0u8; 1024];
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("Connection closed before headers complete".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos + 4; // after \r\n\r\n
            break;
        }
        if buf.len() > 8192 {
            return Err("HTTP headers too large".into());
        }
    }

    let header_str = String::from_utf8_lossy(&buf[..header_end]).to_string();

    let first_line = header_str
        .lines()
        .next()
        .ok_or("Empty request")?
        .to_string();

    // Extract Proxy-Authorization
    let auth_value = extract_header(&header_str, "proxy-authorization");
    let (username, password) = match auth_value {
        Some(val) => parse_basic_auth(&val).ok_or("Invalid Proxy-Authorization")?,
        None => {
            let resp = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n";
            stream.write_all(resp).await.ok();
            return Err("Missing Proxy-Authorization".into());
        }
    };

    let auth = match authenticate_and_parse(&state, &cfg, &username, &password) {
        Some(auth) => auth,
        None => {
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n")
                .await
                .ok();
            return Err("HTTP proxy auth failed".into());
        }
    };
    mark_account_used(&state, auth.account_id.as_deref());
    let filter = auth.filter;

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err("Malformed HTTP request line".into());
    }

    if parts[0].eq_ignore_ascii_case("CONNECT") {
        // --- CONNECT tunnel ---
        let (host, port) = parse_host_port(parts[1], 443)?;
        match connect_through_pool(&state, &filter, &host, port).await {
            Ok((mut upstream, _guard)) => {
                write_all(&mut stream, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                // Forward any data after the headers that was already buffered
                if header_end < buf.len() {
                    upstream
                        .write_all(&buf[header_end..])
                        .await
                        .map_err(|e| e.to_string())?;
                }
                tokio::io::copy_bidirectional(&mut stream, &mut upstream)
                    .await
                    .ok();
                Ok(())
            }
            Err(e) => {
                stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await
                    .ok();
                Err(format!("CONNECT to {host}:{port} failed: {e}"))
            }
        }
    } else {
        // --- Plain HTTP proxy (GET http://host/path ...) ---
        let url = parts[1];
        let (host, port, path) = parse_absolute_url(url)?;

        match connect_through_pool(&state, &filter, &host, port).await {
            Ok((mut upstream, _guard)) => {
                // Rewrite request: absolute URI → relative, strip proxy headers
                let rewritten = rewrite_http_request(&header_str, parts[0], &path);
                upstream
                    .write_all(rewritten.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
                // Forward any body data already buffered
                if header_end < buf.len() {
                    upstream
                        .write_all(&buf[header_end..])
                        .await
                        .map_err(|e| e.to_string())?;
                }
                tokio::io::copy_bidirectional(&mut stream, &mut upstream)
                    .await
                    .ok();
                Ok(())
            }
            Err(e) => {
                stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await
                    .ok();
                Err(format!("Plain HTTP to {host}:{port} failed: {e}"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy pool selection + upstream SOCKS5 client
// ---------------------------------------------------------------------------

/// Pick a random proxy matching filters, ensure binding, and connect to the
/// target through sing-box's local SOCKS5 proxy. Returns the connected stream
/// and a guard that keeps the binding alive.
async fn connect_through_pool(
    state: &Arc<AppState>,
    filter: &ProxyFilter,
    target_host: &str,
    target_port: u16,
) -> Result<(TcpStream, BindingUseGuard), String> {
    let max_attempts = 3;
    let candidates = crate::api::fetch::pick_random_valid_proxies(state, filter, max_attempts)
        .map_err(|e| format!("No proxies available: {e}"))?;

    if candidates.is_empty() {
        return Err("No proxies match the given filters".into());
    }

    let mut last_err = String::new();
    for (attempt, proxy) in candidates.iter().enumerate() {
        let local_port = match crate::bindings::ensure_binding(state, proxy, false).await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "Listener attempt {} bind failed for {}: {e}",
                    attempt + 1,
                    proxy.name
                );
                last_err = e.to_string();
                continue;
            }
        };

        let guard = BindingUseGuard::new(state.clone(), proxy.id.clone());

        match socks5_connect_upstream(local_port, target_host, target_port).await {
            Ok(upstream) => {
                tracing::debug!(
                    "Listener connected via proxy {} (port {local_port}) to {target_host}:{target_port}",
                    proxy.name
                );
                return Ok((upstream, guard));
            }
            Err(e) => {
                tracing::debug!(
                    "Listener attempt {} upstream connect failed via {}: {e}",
                    attempt + 1,
                    proxy.name
                );
                last_err = e;
                // guard dropped here, allow binding cleanup
                continue;
            }
        }
    }

    Err(format!(
        "All {max_attempts} proxy attempts failed: {last_err}"
    ))
}

/// SOCKS5 client: connect to sing-box's local binding and issue a CONNECT.
async fn socks5_connect_upstream(
    local_port: u16,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{local_port}"))
        .await
        .map_err(|e| format!("TCP connect to sing-box port {local_port}: {e}"))?;

    // Negotiate: version 5, 1 method (no-auth)
    write_all(&mut stream, &[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    read_exact(&mut stream, &mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(format!(
            "Upstream SOCKS5 negotiation failed: {:02x} {:02x}",
            resp[0], resp[1]
        ));
    }

    // CONNECT request with domain address
    let host_bytes = target_host.as_bytes();
    let port_bytes = target_port.to_be_bytes();
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]); // ver, connect, rsv, domain
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port_bytes);
    write_all(&mut stream, &req).await?;

    // Read reply (minimum 10 bytes for IPv4 reply)
    let mut reply_hdr = [0u8; 4];
    read_exact(&mut stream, &mut reply_hdr).await?;
    if reply_hdr[1] != 0x00 {
        return Err(format!(
            "Upstream SOCKS5 CONNECT rejected: code {}",
            reply_hdr[1]
        ));
    }

    // Skip BND.ADDR + BND.PORT based on address type
    match reply_hdr[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            read_exact(&mut stream, &mut skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_exact(&mut stream, &mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            read_exact(&mut stream, &mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            read_exact(&mut stream, &mut skip).await?;
        }
        _ => {}
    }

    Ok(stream)
}

// ---------------------------------------------------------------------------
// Authentication & filter parsing
// ---------------------------------------------------------------------------

/// Verify credentials and extract per-connection filters from the username.
/// Returns `None` if auth fails.
struct ProxyAuthentication {
    filter: ProxyFilter,
    account_id: Option<String>,
}

fn authenticate_and_parse(
    state: &AppState,
    cfg: &crate::config::ProxyListenerConfig,
    username: &str,
    password: &str,
) -> Option<ProxyAuthentication> {
    if state.config.proxy_access.static_enabled() {
        if let Some(filter) = authenticate_static_and_parse(cfg, username, password) {
            return Some(ProxyAuthentication {
                filter,
                account_id: None,
            });
        }
    }

    if !state.config.proxy_access.accounts_enabled() {
        return None;
    }

    let (base_username, suffix) = match username.split_once('-') {
        Some((base, suffix)) => (base, Some(suffix)),
        None => (username, None),
    };
    let account = state.proxy_accounts.get(base_username)?;
    if !account.enabled
        || !crate::proxy_account::verify_password(
            &state.config.proxy_access.credential_secret,
            account.value(),
            password,
        )
    {
        return None;
    }

    Some(ProxyAuthentication {
        filter: suffix.map(parse_filter_suffix).unwrap_or_default(),
        account_id: Some(account.id.clone()),
    })
}

fn authenticate_static_and_parse(
    cfg: &crate::config::ProxyListenerConfig,
    username: &str,
    password: &str,
) -> Option<ProxyFilter> {
    if password != cfg.password {
        return None;
    }
    // Username must start with the configured base username
    if !username.starts_with(&cfg.username) {
        return None;
    }
    let suffix = &username[cfg.username.len()..];
    if suffix.is_empty() {
        return Some(ProxyFilter::default());
    }
    // Suffix must start with '-'
    if !suffix.starts_with('-') {
        return None;
    }
    Some(parse_filter_suffix(&suffix[1..]))
}

fn mark_account_used(state: &AppState, account_id: Option<&str>) {
    let Some(account_id) = account_id else {
        return;
    };
    let now = tokio::time::Instant::now();
    let should_write = state
        .proxy_account_last_used
        .get(account_id)
        .map(|last| now.duration_since(*last) >= std::time::Duration::from_secs(60))
        .unwrap_or(true);
    if !should_write {
        return;
    }
    state
        .proxy_account_last_used
        .insert(account_id.to_string(), now);
    if let Err(error) = state.db.touch_proxy_account_last_used(account_id) {
        tracing::warn!(
            account_id,
            "Failed to update proxy account last-used time: {error}"
        );
    }
}

/// Parse `-country-US-residential-chatgpt-google-type-vmess` into a `ProxyFilter`.
fn parse_filter_suffix(suffix: &str) -> ProxyFilter {
    let mut filter = ProxyFilter::default();
    let parts: Vec<&str> = suffix.split('-').collect();
    let mut i = 0;
    while i < parts.len() {
        match parts[i].to_ascii_lowercase().as_str() {
            "country" => {
                if i + 1 < parts.len() {
                    filter.country = Some(parts[i + 1].to_uppercase());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "type" => {
                if i + 1 < parts.len() {
                    filter.proxy_type = Some(parts[i + 1].to_string());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "residential" => {
                filter.residential = true;
                i += 1;
            }
            "chatgpt" => {
                filter.chatgpt = true;
                i += 1;
            }
            "google" => {
                filter.google = true;
                i += 1;
            }
            _ => {
                // Unknown token, skip
                i += 1;
            }
        }
    }
    filter
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn extract_header(headers: &str, name: &str) -> Option<String> {
    for line in headers.lines().skip(1) {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case(name) {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

fn parse_basic_auth(value: &str) -> Option<(String, String)> {
    use base64::Engine;
    let encoded = value.strip_prefix("Basic ")?.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (user, pass) = s.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

fn parse_host_port(addr: &str, default_port: u16) -> Result<(String, u16), String> {
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid port in {addr}"))?;
        Ok((host.to_string(), port))
    } else {
        Ok((addr.to_string(), default_port))
    }
}

fn parse_absolute_url(url: &str) -> Result<(String, u16, String), String> {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| format!("Not an absolute URL: {url}"))?;

    let default_port: u16 = if url.starts_with("https://") { 443 } else { 80 };

    let (host_port, path) = match without_scheme.find('/') {
        Some(pos) => (&without_scheme[..pos], &without_scheme[pos..]),
        None => (without_scheme, "/"),
    };
    let (host, port) = parse_host_port(host_port, default_port)?;
    Ok((host, port, path.to_string()))
}

fn rewrite_http_request(header_str: &str, method: &str, path: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    for (i, line) in header_str.lines().enumerate() {
        if i == 0 {
            // Rewrite request line with relative path
            let parts: Vec<&str> = line.split_whitespace().collect();
            let version = parts.get(2).copied().unwrap_or("HTTP/1.1");
            lines.push(format!("{method} {path} {version}"));
        } else {
            // Skip proxy-specific headers
            if let Some((key, _)) = line.split_once(':') {
                let k = key.trim().to_ascii_lowercase();
                if k == "proxy-authorization" || k == "proxy-connection" {
                    continue;
                }
            }
            lines.push(line.to_string());
        }
    }
    lines.join("\r\n")
}

// ---------------------------------------------------------------------------
// I/O wrappers
// ---------------------------------------------------------------------------

async fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), String> {
    stream
        .read_exact(buf)
        .await
        .map(|_| ())
        .map_err(|e| format!("read: {e}"))
}

async fn write_all(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    stream
        .write_all(data)
        .await
        .map_err(|e| format!("write: {e}"))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_filters_basic() {
        let f = parse_filter_suffix("country-US-residential");
        assert_eq!(f.country, Some("US".into()));
        assert!(f.residential);
        assert!(!f.chatgpt);
    }

    #[test]
    fn parse_filters_all() {
        let f = parse_filter_suffix("chatgpt-google-country-JP-residential-type-vmess");
        assert!(f.chatgpt);
        assert!(f.google);
        assert!(f.residential);
        assert_eq!(f.country, Some("JP".into()));
        assert_eq!(f.proxy_type, Some("vmess".into()));
    }

    #[test]
    fn parse_filters_empty() {
        let f = parse_filter_suffix("");
        assert!(!f.chatgpt);
        assert!(!f.residential);
        assert_eq!(f.country, None);
    }

    #[test]
    fn auth_base_user_only() {
        let cfg = crate::config::ProxyListenerConfig {
            name: "test".into(),
            listen: "0.0.0.0:1080".into(),
            username: "admin".into(),
            password: "secret".into(),
        };
        // Correct base
        let f = authenticate_static_and_parse(&cfg, "admin", "secret");
        assert!(f.is_some());
        // With filters
        let f = authenticate_static_and_parse(&cfg, "admin-country-US", "secret").unwrap();
        assert_eq!(f.country, Some("US".into()));
        // Wrong password
        assert!(authenticate_static_and_parse(&cfg, "admin", "wrong").is_none());
        // Wrong username
        assert!(authenticate_static_and_parse(&cfg, "other", "secret").is_none());
    }

    #[test]
    fn parse_host_port_works() {
        assert_eq!(
            parse_host_port("example.com:8080", 443).unwrap(),
            ("example.com".into(), 8080)
        );
        assert_eq!(
            parse_host_port("example.com", 443).unwrap(),
            ("example.com".into(), 443)
        );
    }

    #[test]
    fn parse_absolute_url_works() {
        let (h, p, path) = parse_absolute_url("http://example.com/foo/bar").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 80);
        assert_eq!(path, "/foo/bar");

        let (h, p, path) = parse_absolute_url("http://example.com:8080/test").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 8080);
        assert_eq!(path, "/test");
    }

    #[test]
    fn basic_auth_parse() {
        // base64("user:pass") = "dXNlcjpwYXNz"
        let (u, p) = parse_basic_auth("Basic dXNlcjpwYXNz").unwrap();
        assert_eq!(u, "user");
        assert_eq!(p, "pass");
    }

    #[test]
    fn header_end_detection() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\nBody"), Some(14));
        assert_eq!(find_header_end(b"Incomplete\r\n"), None);
    }
}
