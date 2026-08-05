use crate::db::{ProxyRow, Subscription};
use crate::error::AppError;
use crate::parser;
use crate::pool::manager::ProxyStatus;
use crate::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct AddSubscriptionRequest {
    pub name: String,
    #[serde(rename = "type", default = "default_sub_type")]
    pub sub_type: String,
    pub url: Option<String>,
    pub content: Option<String>,
    pub refresh_interval_mins: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSubscriptionRequest {
    pub refresh_interval_mins: i32,
}

#[derive(Debug, Deserialize)]
pub struct EditSubscriptionRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub sub_type: String,
    pub url: Option<String>,
    pub content: Option<String>,
    pub refresh_interval_mins: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSubscriptionDefaultsRequest {
    pub refresh_interval_mins: i32,
}

fn default_sub_type() -> String {
    "auto".to_string()
}

fn subscription_user_agent(sub_type: &str) -> &'static str {
    match sub_type.to_ascii_lowercase().as_str() {
        "auto" | "clash" => "Clash.Meta",
        "freeproxy" => "ZenProxy/1.0",
        _ => "v2rayN",
    }
}

async fn fetch_subscription_content(url: &str, sub_type: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .user_agent(subscription_user_agent(sub_type))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch subscription: {e}"))?
        .error_for_status()
        .map_err(|e| format!("Subscription server returned an error: {e}"))?;
    resp.text()
        .await
        .map_err(|e| format!("Failed to read subscription response: {e}"))
}

#[derive(Debug, Clone)]
pub enum SyncMode {
    Normal,
    /// Bind this explicit set for a manual subscription-scoped maintenance run.
    Targeted(Vec<String>),
}

pub struct SyncBindingsResult {
    pub selected_ids: Vec<String>,
    /// IDs selected specifically for the requested maintenance job. This
    /// excludes ordinary prebound serving proxies.
    pub work_ids: Vec<String>,
}

pub async fn list_subscriptions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let subs = state.db.get_subscription_summaries()?;
    let subscriptions: Vec<_> = subs
        .into_iter()
        .map(|sub| {
            json!({
                "id": sub.id,
                "name": sub.name,
                "sub_type": sub.sub_type,
                "url": sub.url,
                "content": sub.content,
                "proxy_count": sub.proxy_count,
                "raw_proxy_count": sub.raw_proxy_count,
                "duplicate_proxy_count": sub.duplicate_proxy_count,
                "refresh_interval_mins": sub.refresh_interval_mins,
                "last_refresh_at": sub.last_refresh_at,
                "created_at": sub.created_at,
                "updated_at": sub.updated_at,
            })
        })
        .collect();
    let default_refresh_interval_mins = state.db.get_subscription_default_refresh_interval_mins(
        state.config.subscription.auto_refresh_interval_mins,
    )?;
    Ok(Json(json!({
        "subscriptions": subscriptions,
        "default_refresh_interval_mins": default_refresh_interval_mins,
    })))
}

pub async fn get_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let subscription = state
        .db
        .get_subscription(&id)?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;
    Ok(Json(json!({ "subscription": subscription })))
}

pub async fn get_subscription_duplicates(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);
    let now = tokio::time::Instant::now();
    let generation = state
        .subscription_duplicate_generation
        .load(std::sync::atomic::Ordering::Acquire);
    if let Some(cached) = state.subscription_duplicate_cache.get(&()) {
        if cached.generation == generation && cached.expires_at > now {
            return Ok(Json(json!({
                "duplicate_stats": cached.stats,
                "overlap_edges": cached.overlaps,
                "cached": true,
            })));
        }
    }

    let _singleflight = state.subscription_duplicate_cache_fill.lock().await;
    loop {
        let generation = state
            .subscription_duplicate_generation
            .load(std::sync::atomic::Ordering::Acquire);
        let now = tokio::time::Instant::now();
        if let Some(cached) = state.subscription_duplicate_cache.get(&()) {
            if cached.generation == generation && cached.expires_at > now {
                return Ok(Json(json!({
                    "duplicate_stats": cached.stats,
                    "overlap_edges": cached.overlaps,
                    "cached": true,
                })));
            }
        }

        let (stats, overlaps) = state.db.get_subscription_duplicate_overview()?;
        // A mutation can invalidate the cache while the aggregate query is in
        // flight. Never publish that stale result; recompute under the same
        // singleflight guard for the new generation instead.
        if state
            .subscription_duplicate_generation
            .load(std::sync::atomic::Ordering::Acquire)
            != generation
        {
            continue;
        }
        state.subscription_duplicate_cache.insert(
            (),
            crate::SubscriptionDuplicateCacheEntry {
                stats: stats.clone(),
                overlaps: overlaps.clone(),
                expires_at: now + CACHE_TTL,
                generation,
            },
        );
        return Ok(Json(json!({
            "duplicate_stats": stats,
            "overlap_edges": overlaps,
            "cached": false,
        })));
    }
}

pub async fn get_subscription_duplicates_for_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    const OVERLAP_LIMIT: i64 = 20;
    const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

    let generation = state
        .subscription_duplicate_generation
        .load(std::sync::atomic::Ordering::Acquire);
    if let Some(cached) = state.subscription_duplicate_details_cache.get(&id) {
        if cached.generation == generation && cached.expires_at > tokio::time::Instant::now() {
            return Ok(Json(json!({
                "duplicate_stats": cached.stats,
                "overlaps": cached.overlaps,
                "cached": true,
                "stale": false,
            })));
        }
    }

    let lock = state
        .subscription_duplicate_details_locks
        .entry(id.clone())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _singleflight = lock.lock().await;

    loop {
        let generation = state
            .subscription_duplicate_generation
            .load(std::sync::atomic::Ordering::Acquire);
        if let Some(cached) = state.subscription_duplicate_details_cache.get(&id) {
            if cached.generation == generation
                && cached.expires_at > tokio::time::Instant::now()
            {
                return Ok(Json(json!({
                    "duplicate_stats": cached.stats,
                    "overlaps": cached.overlaps,
                    "cached": true,
                    "stale": false,
                })));
            }
        }

        let stale = state
            .subscription_duplicate_details_cache
            .get(&id)
            .map(|entry| entry.clone());
        let query_state = state.clone();
        let query_id = id.clone();
        let queried = tokio::task::spawn_blocking(move || {
            if query_state.db.get_subscription(&query_id)?.is_none() {
                return Ok(None);
            }
            query_state
                .db
                .get_subscription_duplicate_details(&query_id, OVERLAP_LIMIT)
                .map(Some)
        })
        .await;

        let queried = match queried {
            Ok(result) => result,
            Err(error) => {
                if let Some(stale) = stale.clone() {
                    tracing::warn!(
                        "Subscription overlap task failed for {id}, serving stale cache: {error}"
                    );
                    return Ok(Json(json!({
                        "duplicate_stats": stale.stats,
                        "overlaps": stale.overlaps,
                        "cached": true,
                        "stale": true,
                    })));
                }
                return Err(AppError::Internal(format!(
                    "Subscription overlap task failed: {error}"
                )));
            }
        };

        let result = match queried {
            Ok(result) => result,
            Err(error) => {
                if let Some(stale) = stale {
                    tracing::warn!(
                        "Subscription overlap refresh failed for {id}, serving stale cache: {error}"
                    );
                    return Ok(Json(json!({
                        "duplicate_stats": stale.stats,
                        "overlaps": stale.overlaps,
                        "cached": true,
                        "stale": true,
                    })));
                }
                return Err(error.into());
            }
        }
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;

        // Do not publish a result computed across a concurrent inventory
        // mutation. Retry while retaining the keyed singleflight lock.
        if state
            .subscription_duplicate_generation
            .load(std::sync::atomic::Ordering::Acquire)
            != generation
        {
            continue;
        }
        let (stats, overlaps) = result;
        state.subscription_duplicate_details_cache.insert(
            id.clone(),
            crate::SubscriptionDuplicateDetailsCacheEntry {
                stats: stats.clone(),
                overlaps: overlaps.clone(),
                expires_at: tokio::time::Instant::now() + CACHE_TTL,
                generation,
            },
        );

        return Ok(Json(json!({
            "duplicate_stats": stats,
            "overlaps": overlaps,
            "cached": false,
            "stale": false,
        })));
    }
}

pub async fn add_subscription(
    State(state): State<Arc<AppState>>,
    body: axum::body::Body,
) -> Result<Json<serde_json::Value>, AppError> {
    // Try to parse as JSON first
    let bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to read body: {e}")))?;

    let req: AddSubscriptionRequest = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

    let name = req.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("Subscription name is required".into()));
    }
    let url = req
        .url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let inline_content = req
        .content
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);

    let refresh_interval_mins = validate_refresh_interval_mins(req.refresh_interval_mins)?;
    if url.is_none() && refresh_interval_mins.unwrap_or(0) > 0 {
        return Err(AppError::BadRequest(
            "Auto-refresh requires a subscription URL".into(),
        ));
    }

    // Make repeated submissions idempotent before downloading or parsing the
    // source. A second atomic check is performed together with the final DB
    // insert to cover concurrent requests that both pass this fast path.
    if let Some(ref url) = url {
        if let Some(existing) = state.db.get_subscription_by_url(url)? {
            return Ok(already_imported_response(existing));
        }
    }

    // Fetch content from URL or use provided content
    let content = if let Some(ref url) = url {
        fetch_subscription_content(url, &req.sub_type)
            .await
            .map_err(AppError::Internal)?
    } else if let Some(ref content) = inline_content {
        content.clone()
    } else {
        return Err(AppError::BadRequest(
            "Either 'url' or 'content' must be provided".into(),
        ));
    };

    // Parse the content
    let parsed = parser::parse_subscription(&content, &req.sub_type);
    if parsed.is_empty() {
        return Err(AppError::BadRequest(
            "No proxies found in subscription content".into(),
        ));
    }
    let raw_proxy_count = parsed.len();
    let parsed = deduplicate_parsed_proxies(parsed);
    let duplicate_proxy_count = raw_proxy_count.saturating_sub(parsed.len());

    let now = chrono::Utc::now().to_rfc3339();
    let sub_id = uuid::Uuid::new_v4().to_string();

    let subscription = Subscription {
        id: sub_id.clone(),
        name: name.to_owned(),
        sub_type: req.sub_type.clone(),
        url: url.clone(),
        content: if url.is_some() { None } else { Some(content) },
        proxy_count: parsed.len() as i32,
        raw_proxy_count: raw_proxy_count as i32,
        duplicate_proxy_count: duplicate_proxy_count as i32,
        refresh_interval_mins,
        last_refresh_at: Some(now.clone()),
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    // Insert proxies
    let mut proxy_rows = Vec::with_capacity(parsed.len());
    for pc in &parsed {
        let proxy_id = uuid::Uuid::new_v4().to_string();
        proxy_rows.push(ProxyRow {
            id: proxy_id.clone(),
            subscription_id: sub_id.clone(),
            name: pc.name.clone(),
            proxy_type: pc.proxy_type.to_string(),
            server: pc.server.clone(),
            port: pc.port as i32,
            config_json: serde_json::to_string(&pc.singbox_outbound).unwrap_or_default(),
            is_valid: false,
            local_port: None,
            error_count: 0,
            last_error: None,
            last_validated: None,
            created_at: now.clone(),
            updated_at: now.clone(),
            orphaned_at: None,
        });
    }

    if let Some(existing) = state
        .db
        .insert_subscription_with_proxies_unless_url_exists(&subscription, &proxy_rows)?
    {
        return Ok(already_imported_response(existing));
    }
    crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
    crate::api::fetch::invalidate_stats_cache(state.as_ref());

    let added = proxy_rows.len();

    tracing::info!(
        "Added subscription '{}' with {added} proxies (discarded {duplicate_proxy_count} exact duplicates)",
        name
    );

    // Assign ports then validate in background (must be sequential, not two separate spawns)
    let state2 = state.clone();
    tokio::spawn(async move {
        tracing::info!("Running initial validation for new proxies...");
        if let Err(e) = crate::pool::validator::validate_all(state2).await {
            tracing::error!("Initial validation failed: {e}");
        }
    });

    Ok(Json(json!({
        "subscription": subscription,
        "proxies_added": added,
        "duplicates_discarded": duplicate_proxy_count,
    })))
}

fn already_imported_response(subscription: Subscription) -> Json<serde_json::Value> {
    let message = format!(
        "Subscription URL already exists as '{}' and was not imported again",
        subscription.name
    );
    Json(json!({
        "message": message,
        "subscription": subscription,
        "already_exists": true,
        "proxies_added": 0,
        "duplicates_discarded": 0,
    }))
}

pub async fn delete_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let proxies = state
        .db
        .get_proxies_by_subscription(&id)?
        .into_iter()
        .collect::<Vec<_>>();
    for proxy in &proxies {
        if let Some(port) = proxy.local_port {
            crate::bindings::cleanup_proxy_binding(&state, &proxy.id, Some(port as u16)).await;
        }
        state.binding_usage.remove(&proxy.id);
    }

    state.pool.remove_by_subscription(&id);
    state.db.delete_subscription(&id)?;
    crate::selection::rebuild(state.as_ref())?;
    crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
    crate::api::fetch::invalidate_stats_cache(state.as_ref());

    // Sync bindings in background
    let state2 = state.clone();
    tokio::spawn(async move {
        let _ = sync_proxy_bindings(&state2, SyncMode::Normal).await;
    });

    Ok(Json(json!({ "message": "Subscription deleted" })))
}

pub async fn update_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateSubscriptionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let sub = state
        .db
        .get_subscription(&id)?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;

    if req.refresh_interval_mins < 0 {
        return Err(AppError::BadRequest(
            "refresh_interval_mins must be >= 0".into(),
        ));
    }
    if sub.url.is_none() && req.refresh_interval_mins > 0 {
        return Err(AppError::BadRequest(
            "Auto-refresh requires a subscription URL".into(),
        ));
    }

    state
        .db
        .update_subscription_refresh_settings(&id, req.refresh_interval_mins)?;

    Ok(Json(json!({
        "message": "Subscription settings updated",
        "refresh_interval_mins": req.refresh_interval_mins,
    })))
}

pub async fn edit_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<EditSubscriptionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut subscription = state
        .db
        .get_subscription(&id)?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;

    let name = req.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("Subscription name is required".into()));
    }

    let sub_type = req.sub_type.trim().to_ascii_lowercase();
    if !matches!(
        sub_type.as_str(),
        "auto"
            | "v2ray"
            | "clash"
            | "base64"
            | "freeproxy"
            | "socks5"
            | "socks4"
            | "http"
            | "https"
    ) {
        return Err(AppError::BadRequest(format!(
            "Unsupported subscription type: {sub_type}"
        )));
    }

    let url = req
        .url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let content = req
        .content
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if url.is_none() && content.is_none() {
        return Err(AppError::BadRequest(
            "Either 'url' or 'content' must be provided".into(),
        ));
    }

    let refresh_interval_mins = validate_refresh_interval_mins(req.refresh_interval_mins)?;
    if url.is_none() && refresh_interval_mins.unwrap_or(0) > 0 {
        return Err(AppError::BadRequest(
            "Auto-refresh requires a subscription URL".into(),
        ));
    }

    let url_changed = subscription.url != url;
    subscription.name = name.to_owned();
    subscription.sub_type = sub_type;
    subscription.url = url;
    subscription.content = if subscription.url.is_some() {
        None
    } else {
        content
    };
    subscription.refresh_interval_mins = refresh_interval_mins;
    subscription.updated_at = chrono::Utc::now().to_rfc3339();

    if url_changed {
        if let Some(existing) = state
            .db
            .update_subscription_settings_unless_url_exists(&subscription)?
        {
            return Err(AppError::BadRequest(format!(
                "该订阅 URL 已被‘{}’使用",
                existing.name
            )));
        }
    } else {
        state.db.update_subscription_settings(&subscription)?;
    }
    crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
    crate::api::fetch::invalidate_stats_cache(state.as_ref());

    Ok(Json(json!({
        "message": "Subscription updated",
        "subscription": subscription,
    })))
}

pub async fn update_subscription_defaults(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateSubscriptionDefaultsRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if req.refresh_interval_mins < 0 {
        return Err(AppError::BadRequest(
            "refresh_interval_mins must be >= 0".into(),
        ));
    }

    state
        .db
        .set_subscription_default_refresh_interval_mins(req.refresh_interval_mins as u64)?;

    Ok(Json(json!({
        "message": "Default subscription refresh settings updated",
        "refresh_interval_mins": req.refresh_interval_mins,
    })))
}

/// Core logic for refreshing a subscription: fetch content, parse, replace proxies.
/// Returns the number of new proxies added, or an error message.
/// Does NOT spawn validation — the caller decides when/how to validate.
///
/// This uses a **smooth replacement** strategy:
/// 1. Fetch & parse first — if it fails, old proxies are untouched.
/// 2. If parse returns 0 proxies, abort (don't wipe the subscription).
/// 3. For proxies whose (server, port, proxy_type) match an existing one,
///    preserve their validation status, error_count, local_port and quality data.
/// 4. Only then handle old proxies that no longer appear in the new list:
///    - explicit Invalid: delete immediately
///    - Valid/Untested: keep as orphaned for fallback or delayed cleanup
pub async fn refresh_subscription_core(
    state: &Arc<AppState>,
    sub: &Subscription,
) -> Result<usize, String> {
    let content = if let Some(ref url) = sub.url {
        fetch_subscription_content(url, &sub.sub_type).await?
    } else if let Some(ref content) = sub.content {
        content.clone()
    } else {
        return Err("No URL or content to refresh".into());
    };

    let parsed = parser::parse_subscription(&content, &sub.sub_type);
    if parsed.is_empty() {
        return Err("Parsed 0 proxies, keeping existing data".into());
    }
    let raw_proxy_count = parsed.len();
    let parsed = deduplicate_parsed_proxies(parsed);
    let duplicate_proxy_count = raw_proxy_count.saturating_sub(parsed.len());

    // Keep every old definition for an endpoint. A source may legitimately
    // contain multiple credentials/transports behind the same server:port, so
    // a single-value map would silently discard all but one during refresh.
    let old_proxies = state
        .db
        .get_proxies_by_subscription(&sub.id)
        .map_err(|e| format!("Failed to load old proxies: {e}"))?;
    let mut old_map: std::collections::HashMap<(String, u16, String), Vec<ProxyRow>> =
        std::collections::HashMap::new();
    for proxy in old_proxies {
        old_map
            .entry((
                proxy.server.to_ascii_lowercase(),
                proxy.port as u16,
                proxy.proxy_type.clone(),
            ))
            .or_default()
            .push(proxy);
    }

    // Match all unchanged definitions before reusing an old endpoint for a
    // changed definition. This makes matching independent of source order and
    // preserves validation/quality data for every unchanged credential.
    let exact_old_matches: Vec<Option<ProxyRow>> = parsed
        .iter()
        .map(|pc| {
            let key = (
                pc.server.to_ascii_lowercase(),
                pc.port,
                pc.proxy_type.to_string(),
            );
            old_map
                .get_mut(&key)
                .and_then(|candidates| take_matching_proxy(candidates, &pc.singbox_outbound))
        })
        .collect();

    let now = chrono::Utc::now().to_rfc3339();
    let mut total = 0;
    let mut kept_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut refreshed_proxy_rows = Vec::new();
    let mut unchanged_pool_updates = Vec::new();
    let mut new_proxy_rows = Vec::new();

    for (pc, exact_old) in parsed.iter().zip(exact_old_matches) {
        let key = (
            pc.server.to_ascii_lowercase(),
            pc.port,
            pc.proxy_type.to_string(),
        );

        let old = exact_old.or_else(|| old_map.get_mut(&key).and_then(take_preferred_proxy));
        if let Some(old) = old {
            // Same endpoint still exists. Preserve health only when the full
            // outbound is unchanged; credentials/transport changes require a
            // fresh validation and fresh quality metadata.
            kept_ids.insert(old.id.clone());

            let new_config = serde_json::to_string(&pc.singbox_outbound).unwrap_or_default();
            let old_value = serde_json::from_str::<serde_json::Value>(&old.config_json).ok();
            let config_changed = old_value.as_ref().is_none_or(|old| {
                !outbound_definitions_equal(old, &pc.singbox_outbound)
            });
            let proxy_type = pc.proxy_type.to_string();
            let row_changed = config_changed
                || old.name != pc.name
                || old.proxy_type != proxy_type
                || !old.server.eq_ignore_ascii_case(&pc.server)
                || old.port != i32::from(pc.port)
                || old.orphaned_at.is_some();

            if row_changed {
                let mut refreshed = old.clone();
                refreshed.name = pc.name.clone();
                refreshed.proxy_type = proxy_type;
                refreshed.server = pc.server.clone();
                refreshed.port = i32::from(pc.port);
                if config_changed {
                    refreshed.config_json = new_config.clone();
                }
                refreshed.updated_at = now.clone();
                refreshed.orphaned_at = None;
                if config_changed {
                    if let Some(port) = old.local_port {
                        crate::bindings::cleanup_proxy_binding(state, &old.id, Some(port as u16))
                            .await;
                    }
                    state.binding_usage.remove(&old.id);
                    state.pool.remove(&old.id);
                    refreshed.is_valid = false;
                    refreshed.local_port = None;
                    refreshed.error_count = 0;
                    refreshed.last_error = None;
                    refreshed.last_validated = None;
                }
                refreshed_proxy_rows.push(refreshed);
            }

            if !config_changed {
                unchanged_pool_updates.push((
                    old.id.clone(),
                    pc.name.clone(),
                    pc.singbox_outbound.clone(),
                ));
            }

            total += 1;
        } else {
            // New proxy — insert fresh
            let proxy_id = uuid::Uuid::new_v4().to_string();
            new_proxy_rows.push(ProxyRow {
                id: proxy_id.clone(),
                subscription_id: sub.id.clone(),
                name: pc.name.clone(),
                proxy_type: pc.proxy_type.to_string(),
                server: pc.server.clone(),
                port: pc.port as i32,
                config_json: serde_json::to_string(&pc.singbox_outbound).unwrap_or_default(),
                is_valid: false,
                local_port: None,
                error_count: 0,
                last_error: None,
                last_validated: None,
                created_at: now.clone(),
                updated_at: now.clone(),
                orphaned_at: None,
            });
            total += 1;
        }
    }

    state
        .db
        .insert_proxies_batch(&refreshed_proxy_rows)
        .map_err(|e| format!("Failed to update existing proxies as a batch: {e}"))?;
    for (id, name, outbound) in unchanged_pool_updates {
        state.pool.update_proxy_config(&id, &name, outbound);
    }
    state
        .db
        .insert_proxies_batch(&new_proxy_rows)
        .map_err(|e| format!("Failed to insert proxies: {e}"))?;
    // Handle old proxies that no longer appear in the new list:
    // - explicit invalid: delete immediately
    // - valid: keep as orphaned fallback
    // - untested: keep as orphaned and let periodic cleanup decide later
    let mut removed_invalid = 0usize;
    let mut orphaned_valid = 0usize;
    let mut orphaned_untested = 0usize;
    let mut orphaned_ids = Vec::new();
    let mut invalid_ids = Vec::new();
    for old in old_map.values().flatten() {
        if old.is_valid {
            orphaned_ids.push(old.id.clone());
            orphaned_valid += 1;
        } else if old.last_validated.is_some() {
            if let Some(port) = old.local_port {
                crate::bindings::cleanup_proxy_binding(state, &old.id, Some(port as u16)).await;
            }
            state.binding_usage.remove(&old.id);
            state.pool.remove(&old.id);
            invalid_ids.push(old.id.clone());
            removed_invalid += 1;
        } else {
            orphaned_ids.push(old.id.clone());
            orphaned_untested += 1;
        }
    }
    state
        .db
        .mark_proxies_orphaned(&orphaned_ids, &now)
        .map_err(|e| format!("Failed to mark removed proxies as orphaned: {e}"))?;
    state
        .db
        .delete_proxies(&invalid_ids)
        .map_err(|e| format!("Failed to delete invalid removed proxies: {e}"))?;

    state
        .db
        .mark_subscription_refreshed(
            &sub.id,
            total as i32,
            raw_proxy_count as i32,
            duplicate_proxy_count as i32,
        )
        .map_err(|e| format!("Failed to update proxy count: {e}"))?;
    crate::selection::rebuild(state)
        .map_err(|error| format!("Failed to rebuild proxy selection index: {error}"))?;
    crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
    crate::api::fetch::invalidate_stats_cache(state.as_ref());

    if removed_invalid > 0 || orphaned_valid > 0 || orphaned_untested > 0 {
        tracing::info!(
            "Refresh '{}': kept {}, new {}, removed_invalid {}, orphaned_valid {}, orphaned_untested {}",
            sub.name,
            kept_ids.len(),
            total - kept_ids.len(),
            removed_invalid,
            orphaned_valid,
            orphaned_untested
        );
    }

    Ok(total)
}

/// Drop equivalent proxy definitions before inserting or validating them.
/// Display names and sing-box tags are ignored; credentials and route settings
/// remain part of the identity.
fn deduplicate_parsed_proxies(proxies: Vec<parser::ProxyConfig>) -> Vec<parser::ProxyConfig> {
    let mut seen = std::collections::HashSet::with_capacity(proxies.len());
    proxies
        .into_iter()
        .filter(|proxy| seen.insert(proxy_definition_key(proxy)))
        .collect()
}

fn take_matching_proxy(
    candidates: &mut Vec<ProxyRow>,
    outbound: &serde_json::Value,
) -> Option<ProxyRow> {
    let index = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            serde_json::from_str::<serde_json::Value>(&candidate.config_json)
                .is_ok_and(|old| outbound_definitions_equal(&old, outbound))
        })
        .min_by_key(|(_, candidate)| candidate.orphaned_at.is_some())
        .map(|(index, _)| index)?;
    Some(candidates.swap_remove(index))
}

fn take_preferred_proxy(candidates: &mut Vec<ProxyRow>) -> Option<ProxyRow> {
    let index = candidates
        .iter()
        .position(|candidate| candidate.orphaned_at.is_none())
        .or_else(|| candidates.len().checked_sub(1))?;
    Some(candidates.swap_remove(index))
}

fn proxy_definition_key(proxy: &parser::ProxyConfig) -> String {
    outbound_definition_key(
        &proxy.proxy_type.to_string(),
        &proxy.server,
        proxy.port,
        &proxy.singbox_outbound,
    )
}

/// Stable identity for a connectable proxy definition. Display-only tags and
/// DNS-name casing do not make two otherwise identical nodes distinct.
pub(crate) fn outbound_definition_key(
    proxy_type: &str,
    server: &str,
    port: u16,
    outbound: &serde_json::Value,
) -> String {
    let mut outbound = outbound.clone();
    normalize_definition_fields(&mut outbound);
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        proxy_type.to_ascii_lowercase(),
        server.to_ascii_lowercase(),
        port,
        canonical_json(&outbound)
    )
}

pub(crate) fn proxy_row_definition_key(proxy: &ProxyRow) -> String {
    serde_json::from_str::<serde_json::Value>(&proxy.config_json)
        .map(|outbound| {
            outbound_definition_key(
                &proxy.proxy_type,
                &proxy.server,
                proxy.port as u16,
                &outbound,
            )
        })
        // A malformed stored definition must never collapse unrelated rows.
        .unwrap_or_else(|_| format!("invalid\u{1f}{}", proxy.id))
}

fn outbound_definitions_equal(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    normalize_definition_fields(&mut left);
    normalize_definition_fields(&mut right);
    left == right
}

fn normalize_definition_fields(outbound: &mut serde_json::Value) {
    if let Some(object) = outbound.as_object_mut() {
        object.remove("tag");
        if let Some(serde_json::Value::String(server)) = object.get_mut("server") {
            *server = server.to_ascii_lowercase();
        }
    }
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_unstable();
            let fields = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        canonical_json(&object[key])
                    )
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", fields.join(","))
        }
        serde_json::Value::Array(array) => format!(
            "[{}]",
            array
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => value.to_string(),
    }
}

pub async fn refresh_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let sub = state
        .db
        .get_subscription(&id)?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;

    let added = refresh_subscription_core(&state, &sub)
        .await
        .map_err(AppError::Internal)?;

    // Validate in background
    let state2 = state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::pool::validator::validate_all(state2).await {
            tracing::error!("Validation after refresh failed: {e}");
        }
    });

    Ok(Json(json!({
        "message": "Subscription refreshed",
        "proxies_added": added,
    })))
}

pub async fn validate_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let sub = state
        .db
        .get_subscription(&id)?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;
    if !crate::pool::validator::start_subscription_validation(
        state,
        sub.id.clone(),
        sub.name.clone(),
    ) {
        return Ok(Json(json!({ "message": "Validation already running" })));
    }
    Ok(Json(json!({
        "message": "Subscription validation started in background",
        "subscription_id": sub.id,
        "subscription_name": sub.name,
    })))
}

pub async fn quality_check_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let sub = state
        .db
        .get_subscription(&id)?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;
    if !crate::quality::checker::start_subscription_quality_check(
        state,
        sub.id.clone(),
        sub.name.clone(),
    ) {
        return Ok(Json(json!({ "message": "Quality check already running" })));
    }
    Ok(Json(json!({
        "message": "Subscription quality check started in background",
        "subscription_id": sub.id,
        "subscription_name": sub.name,
    })))
}

/// Sync proxy bindings dynamically without restarting sing-box.
///
/// Port pool total = max_proxies + batch_size.
/// - Normal: keep a smaller prebound hot set ready.
/// - Validation: keep the hot set plus the current untested validation batch.
///
/// Active relay traffic is preserved even if it falls outside the managed hot set.
pub async fn sync_proxy_bindings(state: &Arc<AppState>, mode: SyncMode) -> SyncBindingsResult {
    let max = state.config.singbox.max_proxies;
    let prebound = state
        .config
        .singbox
        .prebound_proxies
        .min(state.config.singbox.max_proxies);
    let batch = state.config.validation.batch_size;
    let current_active = state.pool.get_all();

    // Snapshot ALL current ports before changes (for sync_bindings diff)
    let all_current_ports: Vec<(String, u16)> = current_active
        .iter()
        .filter_map(|p| p.local_port.map(|port| (p.id.clone(), port)))
        .collect();

    let mut selected = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();
    // Map every complete proxy definition to its single binding representative.
    // Validation may later select an equivalent row owned by another source;
    // in that case the already selected representative does the probe and its
    // result is propagated to every source row.
    let mut definition_representatives = std::collections::HashMap::new();
    let mut work_ids = Vec::new();
    let mut work_id_set = std::collections::HashSet::new();

    for (row, quality) in state.db.get_hot_proxy_records(prebound).unwrap_or_default() {
        let definition = proxy_row_definition_key(&row);
        if !definition_representatives.contains_key(&definition) && seen_ids.insert(row.id.clone())
        {
            definition_representatives.insert(definition, row.id.clone());
            selected.push(crate::pool::manager::ProxyPool::from_db_parts(row, quality));
        }
    }
    if let SyncMode::Targeted(target_ids) = &mode {
        let targeted = match state.db.get_proxy_records(target_ids) {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(
                    "Failed to load {} targeted binding records: {error}",
                    target_ids.len()
                );
                Vec::new()
            }
        };
        for (row, quality) in targeted {
            if row.orphaned_at.is_some() {
                continue;
            }
            let definition = proxy_row_definition_key(&row);
            if let Some(representative_id) = definition_representatives.get(&definition) {
                if work_id_set.insert(representative_id.clone()) {
                    work_ids.push(representative_id.clone());
                }
            } else if seen_ids.insert(row.id.clone()) {
                definition_representatives.insert(definition, row.id.clone());
                work_id_set.insert(row.id.clone());
                work_ids.push(row.id.clone());
                selected.push(crate::pool::manager::ProxyPool::from_db_parts(row, quality));
            }
        }
    }

    let mut managed_ids = std::collections::HashSet::new();
    for proxy in selected
        .iter()
        .filter(|p| p.status == ProxyStatus::Valid)
        .take(prebound)
    {
        managed_ids.insert(proxy.id.clone());
    }
    match &mode {
        SyncMode::Targeted(_) => {
            for id in &work_ids {
                managed_ids.insert(id.clone());
            }
        }
        SyncMode::Normal => {}
    }

    let mut desired_ids = managed_ids.clone();
    let selected_id_set: std::collections::HashSet<String> =
        selected.iter().map(|proxy| proxy.id.clone()).collect();
    for proxy in &current_active {
        if proxy.local_port.is_none() {
            continue;
        }
        let Some(usage) = state.binding_usage.get(&proxy.id) else {
            continue;
        };
        if usage.in_flight == 0 {
            continue;
        }
        desired_ids.insert(proxy.id.clone());
        if !selected_id_set.contains(&proxy.id) {
            selected.push(proxy.clone());
        }
    }

    let selected_ids: Vec<String> = selected.iter().map(|p| p.id.clone()).collect();

    let mode_str = match &mode {
        SyncMode::Normal => "normal",
        SyncMode::Targeted(_) => "targeted",
    };
    tracing::info!(
        "Syncing bindings: {} selected, {} desired (mode={}, max={}, prebound={}, batch={})",
        selected.len(),
        desired_ids.len(),
        mode_str,
        max,
        prebound,
        batch,
    );

    let selected_id_set: std::collections::HashSet<&str> =
        selected_ids.iter().map(|id| id.as_str()).collect();
    let mut cleared_ids = std::collections::HashSet::new();
    for p in &current_active {
        if p.local_port.is_some() && !selected_id_set.contains(p.id.as_str()) {
            cleared_ids.insert(p.id.clone());
        }
    }

    let mut mgr = state.singbox.lock().await;
    let desired: Vec<(String, serde_json::Value)> = selected
        .iter()
        .filter(|p| desired_ids.contains(&p.id))
        .map(|p| (p.id.clone(), p.singbox_outbound.clone()))
        .collect();
    let assignments = mgr.sync_bindings(&desired, &all_current_ports).await;
    drop(mgr);

    // Update pool and DB
    for proxy in &mut selected {
        proxy.local_port = None;
    }
    state.pool.replace_all(selected);
    for (id, port) in &assignments {
        state.pool.set_local_port(id, *port);
    }
    let assigned_ids: std::collections::HashSet<&str> =
        assignments.iter().map(|(id, _)| id.as_str()).collect();
    for id in &selected_ids {
        if !assigned_ids.contains(id.as_str()) {
            state.pool.clear_local_port(id);
            cleared_ids.insert(id.clone());
        }
    }
    let assignments_for_db: Vec<_> = assignments
        .iter()
        .map(|(id, port)| (id.clone(), *port))
        .collect();
    let cleared_ids: Vec<_> = cleared_ids.into_iter().collect();
    if let Err(error) = state
        .db
        .sync_proxy_local_ports(&assignments_for_db, &cleared_ids)
    {
        tracing::warn!("Failed to persist reconciled proxy binding state: {error}");
    }

    let active_ports: Vec<u16> = assignments.iter().map(|(_, port)| *port).collect();
    crate::bindings::reconcile_binding_usage(state, &assignments, &managed_ids);
    crate::api::relay::invalidate_relay_clients(state, &active_ports);

    SyncBindingsResult {
        selected_ids,
        work_ids,
    }
}

fn validate_refresh_interval_mins(value: Option<i32>) -> Result<Option<i32>, AppError> {
    match value {
        Some(interval) if interval < 0 => Err(AppError::BadRequest(
            "refresh_interval_mins must be >= 0".into(),
        )),
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        deduplicate_parsed_proxies, proxy_row_definition_key, subscription_user_agent,
        take_matching_proxy,
    };
    use crate::db::ProxyRow;
    use crate::parser::{ProxyConfig, ProxyType};
    use serde_json::json;

    fn proxy(name: &str, tag: &str, password: &str) -> ProxyConfig {
        ProxyConfig {
            name: name.into(),
            proxy_type: ProxyType::Trojan,
            server: "EXAMPLE.com".into(),
            port: 443,
            singbox_outbound: json!({
                "type": "trojan",
                "tag": tag,
                "server": "example.com",
                "server_port": 443,
                "password": password,
                "tls": {"enabled": true}
            }),
        }
    }

    #[test]
    fn exact_source_duplicates_are_removed_before_validation() {
        let proxies = vec![
            proxy("first name", "generated-1", "same-secret"),
            proxy("other name", "generated-2", "same-secret"),
            proxy("different credential", "generated-3", "other-secret"),
        ];

        let deduplicated = deduplicate_parsed_proxies(proxies);
        assert_eq!(deduplicated.len(), 2);
        assert_eq!(deduplicated[0].name, "first name");
        assert_eq!(deduplicated[1].name, "different credential");
    }

    #[test]
    fn subscription_user_agent_requests_the_selected_format() {
        assert_eq!(subscription_user_agent("auto"), "Clash.Meta");
        assert_eq!(subscription_user_agent("clash"), "Clash.Meta");
        assert_eq!(subscription_user_agent("freeproxy"), "ZenProxy/1.0");
        assert_eq!(subscription_user_agent("base64"), "v2rayN");
        assert_eq!(subscription_user_agent("v2ray"), "v2rayN");
    }

    #[test]
    fn refresh_match_keeps_distinct_credentials_on_the_same_endpoint() {
        let mut candidates = vec![
            proxy_row("old-a", "secret-a"),
            proxy_row("old-b", "secret-b"),
        ];
        let wanted = proxy("new-b", "generated", "secret-b").singbox_outbound;

        let matched = take_matching_proxy(&mut candidates, &wanted).unwrap();

        assert_eq!(matched.id, "old-b");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id, "old-a");
    }

    #[test]
    fn cross_subscription_identity_ignores_only_display_tag_and_server_case() {
        let mut first = proxy_row("source-a", "same-secret");
        first.subscription_id = "subscription-a".into();
        first.server = "EXAMPLE.COM".into();

        let mut second = proxy_row("source-b", "same-secret");
        second.subscription_id = "subscription-b".into();
        second.name = "another display name".into();
        let mut second_config: serde_json::Value =
            serde_json::from_str(&second.config_json).unwrap();
        second_config["tag"] = json!("different-generated-tag");
        second.config_json = second_config.to_string();

        let different_credential = proxy_row("source-c", "other-secret");

        assert_eq!(
            proxy_row_definition_key(&first),
            proxy_row_definition_key(&second)
        );
        assert_ne!(
            proxy_row_definition_key(&first),
            proxy_row_definition_key(&different_credential)
        );
    }

    fn proxy_row(id: &str, password: &str) -> ProxyRow {
        ProxyRow {
            id: id.into(),
            subscription_id: "subscription".into(),
            name: id.into(),
            proxy_type: "trojan".into(),
            server: "example.com".into(),
            port: 443,
            config_json: proxy(id, id, password).singbox_outbound.to_string(),
            is_valid: true,
            local_port: None,
            error_count: 0,
            last_error: None,
            last_validated: None,
            created_at: String::new(),
            updated_at: String::new(),
            orphaned_at: None,
        }
    }
}
