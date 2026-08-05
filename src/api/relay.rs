use crate::api::auth;
use crate::api::fetch::{find_proxy_snapshot, pick_random_valid_proxies};
use crate::bindings::BindingUseGuard;
use crate::error::AppError;
use crate::pool::manager::{PoolProxy, ProxyFilter, ProxyStatus};
use crate::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use futures_util::Stream;
use pin_project_lite::pin_project;
use serde::Deserialize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Headers that should NOT be forwarded from the user request to the target.
/// Strip hop-by-hop headers plus reverse-proxy/CDN-added source headers.
const SKIP_HEADERS: &[&str] = &[
    "host",
    "connection",
    "transfer-encoding",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
    "via",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "cf-ipcountry",
    "cf-ray",
    "cf-visitor",
    "cf-ew-via",
    "cdn-loop",
];

#[derive(Debug, Deserialize)]
pub struct RelayParams {
    pub url: Option<String>,
    pub method: Option<String>,
    pub proxy_id: Option<String>,
    pub api_key: Option<String>,
    // Quality filters
    #[serde(default)]
    pub chatgpt: bool,
    #[serde(default)]
    pub google: bool,
    #[serde(default)]
    pub residential: bool,
    pub risk_max: Option<f64>,
    pub country: Option<String>,
    #[serde(rename = "type")]
    pub proxy_type: Option<String>,
}

pub async fn relay_request(
    State(state): State<Arc<AppState>>,
    Query(params): Query<RelayParams>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    // Authenticate: relay requires api_key query parameter only,
    // so Authorization/Cookie headers are free for the target.
    let api_key = params
        .api_key
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Relay requires 'api_key' query parameter".into()))?;
    auth::authenticate_query_api_key_only(&state, api_key)?;

    let target_url = params
        .url
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Missing 'url' parameter".into()))?;
    let target_url = validate_target_url(target_url)?;

    let method = params.method.as_deref().unwrap_or("GET");

    let filter = ProxyFilter {
        chatgpt: params.chatgpt,
        google: params.google,
        residential: params.residential,
        risk_max: params.risk_max,
        country: params.country,
        proxy_type: params.proxy_type,
        proxy_id: params.proxy_id,
        count: None,
    };

    // Try to find a working proxy
    let max_retries = 5;

    // If specific proxy requested
    if let Some(ref id) = filter.proxy_id {
        if let Some(proxy) = find_proxy_snapshot(&state, id)? {
            let local_port = match crate::bindings::ensure_binding(&state, &proxy, false).await {
                Ok(port) => port,
                Err(e) => {
                    record_relay_failure(&state, &proxy, None, &e.to_string()).await;
                    return Err(e);
                }
            };
            let usage = BindingUseGuard::new(state.clone(), proxy.id.clone());
            let client = get_or_create_client(&state, local_port, &proxy)?;
            match do_relay(&client, target_url.as_str(), method, &headers, &body).await {
                Ok(resp) => {
                    return Ok(build_streaming_response(resp, &proxy, None, usage));
                }
                Err(e) => {
                    record_relay_failure(&state, &proxy, Some(local_port), &e).await;
                    return Err(AppError::Internal(format!("Relay failed: {e}")));
                }
            }
        }
        return Err(AppError::NotFound("Specified proxy not found".into()));
    }

    let candidates = pick_random_valid_proxies(&state, &filter, max_retries)?;
    if candidates.is_empty() {
        return Err(AppError::NotFound(
            "No proxies match the given filters".into(),
        ));
    }

    for (attempt, proxy) in candidates.iter().enumerate() {
        let local_port = match crate::bindings::ensure_binding(&state, proxy, false).await {
            Ok(port) => port,
            Err(e) => {
                tracing::debug!(
                    "Relay attempt {} failed to bind proxy {}: {}",
                    attempt + 1,
                    proxy.name,
                    e
                );
                record_relay_failure(&state, proxy, None, &e.to_string()).await;
                continue;
            }
        };

        let usage = BindingUseGuard::new(state.clone(), proxy.id.clone());
        let client = get_or_create_client(&state, local_port, proxy)?;
        match do_relay(&client, target_url.as_str(), method, &headers, &body).await {
            Ok(resp) => {
                return Ok(build_streaming_response(
                    resp,
                    proxy,
                    Some(attempt as u32 + 1),
                    usage,
                ));
            }
            Err(e) => {
                tracing::debug!(
                    "Relay attempt {} failed with proxy {}: {e}",
                    attempt + 1,
                    proxy.name
                );
                record_relay_failure(&state, proxy, Some(local_port), &e).await;
                continue;
            }
        }
    }

    Err(AppError::Internal(format!(
        "All {max_retries} relay attempts failed"
    )))
}

fn validate_target_url(target_url: &str) -> Result<reqwest::Url, AppError> {
    let parsed = reqwest::Url::parse(target_url)
        .map_err(|e| AppError::BadRequest(format!("Invalid 'url' parameter: {e}")))?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        other => Err(AppError::BadRequest(format!(
            "Unsupported relay url scheme '{other}', only http/https are allowed"
        ))),
    }
}

async fn record_relay_failure(
    state: &Arc<AppState>,
    proxy: &PoolProxy,
    local_port: Option<u16>,
    error: &str,
) {
    tracing::debug!("Relay failure recorded for {}: {}", proxy.name, error);

    // Stop selecting this definition immediately while retaining other
    // definitions in the same measured-exit group as availability fallbacks.
    crate::selection::exclude_definition(state.as_ref(), proxy);

    crate::bindings::cleanup_proxy_binding(state, &proxy.id, local_port).await;

    if should_delete_proxy_after_relay_failure(error) {
        tracing::warn!(
            "Deleting proxy {} after permanent relay failure: {}",
            proxy.name,
            error
        );
        state.binding_usage.remove(&proxy.id);
        state.pool.remove(&proxy.id);
        state.db.delete_proxy(&proxy.id).ok();
        crate::api::fetch::invalidate_stats_cache(state.as_ref());
        crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
        return;
    }

    state.pool.increment_error(&proxy.id);
    state.pool.set_status(&proxy.id, ProxyStatus::Untested);
    state
        .db
        .mark_proxy_relay_failed(
            &proxy.id,
            error,
            state.config.validation.error_threshold,
        )
        .ok();
    crate::api::fetch::invalidate_stats_cache(state.as_ref());
    crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
}

fn should_delete_proxy_after_relay_failure(error: &str) -> bool {
    let normalized = error.to_ascii_lowercase();
    normalized.contains("failed to create outbound:")
        || normalized.contains("invalid public_key")
        || normalized.contains("unsupported flow")
}

#[cfg(test)]
mod tests {
    use super::{should_delete_proxy_after_relay_failure, SKIP_HEADERS};

    #[test]
    fn permanent_binding_errors_are_deleted() {
        assert!(should_delete_proxy_after_relay_failure(
            "Internal error: Failed to create binding: failed to create outbound: invalid public_key"
        ));
        assert!(should_delete_proxy_after_relay_failure(
            "Bindings API returned 500: unsupported flow: xtls-rprx-vision-udp443"
        ));
    }

    #[test]
    fn transient_relay_errors_are_not_deleted() {
        assert!(!should_delete_proxy_after_relay_failure(
            "error sending request for url (https://example.com/)"
        ));
        assert!(!should_delete_proxy_after_relay_failure("HTTP 502"));
    }

    #[test]
    fn target_auth_headers_are_forwarded() {
        assert!(!SKIP_HEADERS.contains(&"authorization"));
        assert!(!SKIP_HEADERS.contains(&"cookie"));
    }
}

/// Get a cached reqwest::Client for the given proxy port, or create one.
fn get_or_create_client(
    state: &AppState,
    local_port: u16,
    bound_proxy: &PoolProxy,
) -> Result<reqwest::Client, AppError> {
    let definition = crate::api::subscription::outbound_definition_key(
        &bound_proxy.proxy_type,
        &bound_proxy.server,
        bound_proxy.port,
        &bound_proxy.singbox_outbound,
    );
    let key = (local_port, definition);
    if let Some(client) = state.relay_clients.get(&key) {
        return Ok(client.clone());
    }

    let proxy_addr = format!("http://127.0.0.1:{local_port}");
    let proxy = reqwest::Proxy::all(&proxy_addr)
        .map_err(|e| AppError::Internal(format!("Proxy config error: {e}")))?;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(10);

    if state.config.relay.timeout_secs > 0 {
        builder = builder.timeout(std::time::Duration::from_secs(
            state.config.relay.timeout_secs,
        ));
    }

    let client = builder
        .build()
        .map_err(|e| AppError::Internal(format!("Client build error: {e}")))?;

    // Remove any client left behind by the previous definition assigned to
    // this port before making the new client visible.
    state
        .relay_clients
        .retain(|(port, _), _| *port != local_port);
    state.relay_clients.insert(key, client.clone());
    Ok(client)
}

/// Invalidate cached clients for ports that are no longer in use.
pub fn invalidate_relay_clients(state: &AppState, active_ports: &[u16]) {
    let stale: Vec<(u16, String)> = state
        .relay_clients
        .iter()
        .map(|e| e.key().clone())
        .filter(|(port, _)| !active_ports.contains(port))
        .collect();
    for key in stale {
        state.relay_clients.remove(&key);
    }
}

/// Headers that should NOT be forwarded from the target response back to the user.
const SKIP_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "transfer-encoding",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

pin_project! {
    struct TrackedBodyStream<S> {
        #[pin]
        inner: S,
        guard: Option<BindingUseGuard>,
    }
}

impl<S> Stream for TrackedBodyStream<S>
where
    S: Stream,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let poll = this.inner.as_mut().poll_next(cx);
        if matches!(poll, Poll::Ready(None)) {
            this.guard.take();
        }
        poll
    }
}

/// Build a streaming axum Response from a reqwest::Response, attaching X-Proxy-* headers.
fn build_streaming_response(
    resp: reqwest::Response,
    proxy: &PoolProxy,
    attempt: Option<u32>,
    guard: BindingUseGuard,
) -> Response {
    let status = resp.status();

    // Collect response headers before consuming the body
    let resp_headers = resp.headers().clone();

    let encoded_name = percent_encoding::utf8_percent_encode(
        &proxy.name,
        percent_encoding::NON_ALPHANUMERIC,
    ).to_string();

    // Stream the response body without buffering
    let body = axum::body::Body::from_stream(TrackedBodyStream {
        inner: resp.bytes_stream(),
        guard: Some(guard),
    });

    let mut response = (status, body).into_response();

    let h = response.headers_mut();

    // Forward all response headers from target (except hop-by-hop)
    for (name, value) in resp_headers.iter() {
        let key = name.as_str().to_lowercase();
        if SKIP_RESPONSE_HEADERS.contains(&key.as_str()) {
            continue;
        }
        h.insert(name.clone(), value.clone());
    }

    // Add proxy metadata headers
    h.insert("X-Proxy-Id", proxy.id.parse().unwrap());
    h.insert("X-Proxy-Name", encoded_name.parse().unwrap());
    h.insert("X-Proxy-Server", format!("{}:{}", proxy.server, proxy.port).parse().unwrap());
    if let Some(q) = &proxy.quality {
        if let Some(ref ip) = q.ip_address {
            if let Ok(v) = ip.parse() { h.insert("X-Proxy-IP", v); }
        }
        if let Some(ref country) = q.country {
            if let Ok(v) = country.parse() { h.insert("X-Proxy-Country", v); }
        }
    }
    if let Some(a) = attempt {
        h.insert("X-Proxy-Attempt", a.to_string().parse().unwrap());
    }
    response
}

/// Send the relay request through the proxy, forwarding user headers and body.
/// Returns the raw reqwest::Response for streaming.
async fn do_relay(
    client: &reqwest::Client,
    target_url: &str,
    method: &str,
    user_headers: &HeaderMap,
    body: &[u8],
) -> Result<reqwest::Response, String> {
    let mut req = match method.to_uppercase().as_str() {
        "POST" => client.post(target_url),
        "PUT" => client.put(target_url),
        "DELETE" => client.delete(target_url),
        "PATCH" => client.patch(target_url),
        "HEAD" => client.head(target_url),
        _ => client.get(target_url),
    };

    // Forward user headers (excluding hop-by-hop and sensitive ones)
    for (name, value) in user_headers.iter() {
        let key = name.as_str().to_lowercase();
        if SKIP_HEADERS.contains(&key.as_str()) {
            continue;
        }
        req = req.header(name.clone(), value.clone());
    }

    // Forward request body for any method that has one
    if !body.is_empty() {
        req = req.body(body.to_vec());
    }

    req.send().await.map_err(|e| e.to_string())
}
