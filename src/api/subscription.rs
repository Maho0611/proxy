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
pub struct UpdateSubscriptionDefaultsRequest {
    pub refresh_interval_mins: i32,
}

fn default_sub_type() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Copy)]
pub enum SyncMode {
    Normal,
    Validation,
    QualityCheck,
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
    let subs = state.db.get_subscriptions()?;
    let (duplicate_stats, overlap_edges) = state.db.get_subscription_duplicate_overview()?;
    let stats_by_subscription: std::collections::HashMap<_, _> = duplicate_stats
        .into_iter()
        .map(|stats| (stats.subscription_id.clone(), stats))
        .collect();
    let subscriptions: Vec<_> = subs
        .into_iter()
        .map(|sub| {
            let duplicate_stats = stats_by_subscription.get(&sub.id);
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
                "duplicate_stats": duplicate_stats,
            })
        })
        .collect();
    let default_refresh_interval_mins = state.db.get_subscription_default_refresh_interval_mins(
        state.config.subscription.auto_refresh_interval_mins,
    )?;
    Ok(Json(json!({
        "subscriptions": subscriptions,
        "overlap_edges": overlap_edges,
        "default_refresh_interval_mins": default_refresh_interval_mins,
    })))
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

    let refresh_interval_mins = validate_refresh_interval_mins(req.refresh_interval_mins)?;
    if req.url.is_none() && refresh_interval_mins.unwrap_or(0) > 0 {
        return Err(AppError::BadRequest(
            "Auto-refresh requires a subscription URL".into(),
        ));
    }

    // Fetch content from URL or use provided content
    let content = if let Some(ref url) = req.url {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to fetch subscription: {e}")))?;
        resp.text()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read response: {e}")))?
    } else if let Some(ref content) = req.content {
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
        name: req.name.clone(),
        sub_type: req.sub_type.clone(),
        url: req.url.clone(),
        content: if req.url.is_some() {
            None
        } else {
            Some(content)
        },
        proxy_count: parsed.len() as i32,
        raw_proxy_count: raw_proxy_count as i32,
        duplicate_proxy_count: duplicate_proxy_count as i32,
        refresh_interval_mins,
        last_refresh_at: Some(now.clone()),
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    state.db.insert_subscription(&subscription)?;

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

    state.db.insert_proxies_batch(&proxy_rows)?;
    state.db.inherit_exact_duplicate_states(
        &proxy_rows
            .iter()
            .map(|proxy| proxy.id.clone())
            .collect::<Vec<_>>(),
    )?;
    crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
    crate::api::fetch::invalidate_stats_cache(state.as_ref());

    let added = proxy_rows.len();

    tracing::info!(
        "Added subscription '{}' with {added} proxies (discarded {duplicate_proxy_count} exact duplicates)",
        req.name
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
        crate::bindings::cleanup_proxy_binding(
            &state,
            &proxy.id,
            proxy.local_port.map(|port| port as u16),
        )
        .await;
        state.binding_usage.remove(&proxy.id);
    }

    state.pool.remove_by_subscription(&id);
    state.db.delete_subscription(&id)?;
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
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch: {e}"))?;
        resp.text()
            .await
            .map_err(|e| format!("Failed to read: {e}"))?
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
    let mut new_proxy_rows = Vec::new();
    let mut state_inheritance_ids = Vec::new();

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
            let config_changed = old_value.as_ref().map_or(true, |old| {
                !outbound_definitions_equal(old, &pc.singbox_outbound)
            });
            if config_changed {
                crate::bindings::cleanup_proxy_binding(
                    state,
                    &old.id,
                    old.local_port.map(|port| port as u16),
                )
                .await;
                state.binding_usage.remove(&old.id);
                state.pool.remove(&old.id);
                state
                    .db
                    .reset_proxy_after_config_change(&old.id, &pc.name, &new_config)
                    .map_err(|e| format!("Failed to reset changed proxy config: {e}"))?;
                state_inheritance_ids.push(old.id.clone());
            } else {
                state
                    .db
                    .update_proxy_config(&old.id, &pc.name, &new_config)
                    .map_err(|e| format!("Failed to update proxy config: {e}"))?;
                state
                    .pool
                    .update_proxy_config(&old.id, &pc.name, pc.singbox_outbound.clone());
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
            state_inheritance_ids.push(proxy_id);
            total += 1;
        }
    }

    state
        .db
        .insert_proxies_batch(&new_proxy_rows)
        .map_err(|e| format!("Failed to insert proxies: {e}"))?;
    state
        .db
        .inherit_exact_duplicate_states(&state_inheritance_ids)
        .map_err(|e| format!("Failed to inherit exact-duplicate state: {e}"))?;

    // Handle old proxies that no longer appear in the new list:
    // - explicit invalid: delete immediately
    // - valid: keep as orphaned fallback
    // - untested: keep as orphaned and let periodic cleanup decide later
    let mut removed_invalid = 0usize;
    let mut orphaned_valid = 0usize;
    let mut orphaned_untested = 0usize;
    for old in old_map.values().flatten() {
        if old.is_valid {
            state.db.mark_proxy_orphaned(&old.id, &now).ok();
            orphaned_valid += 1;
        } else if old.last_validated.is_some() {
            crate::bindings::cleanup_proxy_binding(
                state,
                &old.id,
                old.local_port.map(|port| port as u16),
            )
            .await;
            state.binding_usage.remove(&old.id);
            state.pool.remove(&old.id);
            state.db.delete_proxy(&old.id).ok();
            removed_invalid += 1;
        } else {
            state.db.mark_proxy_orphaned(&old.id, &now).ok();
            orphaned_untested += 1;
        }
    }

    state
        .db
        .mark_subscription_refreshed(
            &sub.id,
            total as i32,
            raw_proxy_count as i32,
            duplicate_proxy_count as i32,
        )
        .map_err(|e| format!("Failed to update proxy count: {e}"))?;
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
        .map_err(|e| AppError::Internal(e))?;

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

/// Sync proxy bindings dynamically without restarting sing-box.
///
/// Port pool total = max_proxies + batch_size.
/// - Normal: keep a smaller prebound hot set ready.
/// - Validation: keep the hot set plus the current untested validation batch.
/// - QualityCheck: keep the hot set plus a temporary batch of stale-quality proxies.
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

    for (row, quality) in state.db.get_hot_proxy_records(prebound).unwrap_or_default() {
        let definition = proxy_row_definition_key(&row);
        if !definition_representatives.contains_key(&definition) && seen_ids.insert(row.id.clone())
        {
            definition_representatives.insert(definition, row.id.clone());
            selected.push(crate::pool::manager::ProxyPool::from_db_parts(row, quality));
        }
    }
    if matches!(mode, SyncMode::Validation) {
        let cfg = &state.config.validation;
        let (new_limit, valid_limit, invalid_limit) = validation_batch_limits(
            batch,
            cfg.new_proxy_percent,
            cfg.valid_recheck_percent,
            cfg.invalid_retry_percent,
            cfg.valid_recheck_hours > 0,
        );
        let now = chrono::Utc::now();
        let valid_before =
            (now - chrono::Duration::hours(cfg.valid_recheck_hours.max(1) as i64)).to_rfc3339();
        let retry_before = (now - chrono::Duration::minutes(180)).to_rfc3339();
        let orphaned_before = (now
            - chrono::Duration::hours(state.config.subscription.orphaned_valid_grace_hours as i64))
        .to_rfc3339();
        for (row, quality) in state
            .db
            .get_validation_proxy_records(
                new_limit,
                valid_limit,
                invalid_limit.min(cfg.retry_invalid_per_run),
                &valid_before,
                &retry_before,
                &orphaned_before,
                cfg.error_threshold,
            )
            .unwrap_or_default()
        {
            let definition = proxy_row_definition_key(&row);
            if let Some(representative_id) = definition_representatives.get(&definition) {
                // Validate the one already-bound representative. A successful
                // round synchronizes every exact source copy, so this legacy
                // mismatch cannot keep reappearing in later rounds.
                if !work_ids.contains(representative_id) {
                    work_ids.push(representative_id.clone());
                }
            } else if seen_ids.insert(row.id.clone()) {
                definition_representatives.insert(definition, row.id.clone());
                work_ids.push(row.id.clone());
                selected.push(crate::pool::manager::ProxyPool::from_db_parts(row, quality));
            }
        }
    }
    let quality_stale_hours = state.config.quality.stale_hours.max(1);
    if matches!(mode, SyncMode::QualityCheck) {
        let stale_before =
            (chrono::Utc::now() - chrono::Duration::hours(quality_stale_hours as i64)).to_rfc3339();
        for (row, quality) in state
            .db
            .get_due_quality_proxy_records(
                batch,
                &stale_before,
                crate::quality::checker::MAX_INCOMPLETE_RETRIES,
                crate::quality::checker::QUALITY_SCHEMA_VERSION,
            )
            .unwrap_or_default()
        {
            let definition = proxy_row_definition_key(&row);
            if definition_representatives.contains_key(&definition) {
                // Old databases may contain exact copies whose quality rows
                // predate shared-result propagation. Reuse the freshest known
                // copy rather than allocating another sing-box binding.
                if let Err(error) = state
                    .db
                    .inherit_exact_duplicate_states(std::slice::from_ref(&row.id))
                {
                    tracing::warn!("Failed to inherit exact-duplicate quality state: {error}");
                }
            } else if seen_ids.insert(row.id.clone()) {
                definition_representatives.insert(definition, row.id.clone());
                selected.push(crate::pool::manager::ProxyPool::from_db_parts(row, quality));
            }
        }
    }

    let mut managed_ids = std::collections::HashSet::new();
    let now = chrono::Utc::now();
    for proxy in selected
        .iter()
        .filter(|p| p.status == ProxyStatus::Valid)
        .take(prebound)
    {
        managed_ids.insert(proxy.id.clone());
    }
    match mode {
        SyncMode::Validation => {
            for id in &work_ids {
                managed_ids.insert(id.clone());
            }
        }
        SyncMode::QualityCheck => {
            let mut extra = 0usize;
            for proxy in selected.iter().filter(|p| p.status == ProxyStatus::Valid) {
                if extra >= batch {
                    break;
                }
                if crate::quality::checker::needs_quality_check(proxy, &now, quality_stale_hours) {
                    if managed_ids.insert(proxy.id.clone()) {
                        extra += 1;
                    }
                }
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

    let mode_str = match mode {
        SyncMode::Normal => "normal",
        SyncMode::Validation => "validation",
        SyncMode::QualityCheck => "quality-check",
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
    for p in &current_active {
        if p.local_port.is_some() && !selected_id_set.contains(p.id.as_str()) {
            state.db.update_proxy_local_port_null(&p.id).ok();
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
        state.db.update_proxy_local_port(id, *port as i32).ok();
        state.db.clear_proxy_binding_failures(id).ok();
    }
    let assigned_ids: std::collections::HashSet<&str> =
        assignments.iter().map(|(id, _)| id.as_str()).collect();
    for id in &selected_ids {
        if !assigned_ids.contains(id.as_str()) {
            state.pool.clear_local_port(id);
            state.db.update_proxy_local_port_null(id).ok();
        }
    }

    let active_ports: Vec<u16> = assignments.iter().map(|(_, port)| *port).collect();
    crate::bindings::reconcile_binding_usage(state, &assignments, &managed_ids);
    crate::api::relay::invalidate_relay_clients(state, &active_ports);

    SyncBindingsResult {
        selected_ids,
        work_ids,
    }
}

pub(crate) fn validation_batch_limits(
    batch: usize,
    new_percent: u8,
    valid_percent: u8,
    invalid_percent: u8,
    valid_enabled: bool,
) -> (usize, usize, usize) {
    if batch == 0 {
        return (0, 0, 0);
    }
    let new_percent = new_percent as usize;
    let valid_percent = if valid_enabled {
        valid_percent as usize
    } else {
        0
    };
    let invalid_percent = invalid_percent as usize;
    let total = new_percent + valid_percent + invalid_percent;
    if total == 0 {
        return (batch, 0, 0);
    }

    let mut new_limit = batch * new_percent / total;
    let mut valid_limit = batch * valid_percent / total;
    let mut invalid_limit = batch * invalid_percent / total;
    if new_percent > 0 {
        new_limit = new_limit.max(1);
    }
    if valid_percent > 0 {
        valid_limit = valid_limit.max(1);
    }
    if invalid_percent > 0 {
        invalid_limit = invalid_limit.max(1);
    }

    while new_limit + valid_limit + invalid_limit > batch {
        if new_limit >= valid_limit && new_limit >= invalid_limit && new_limit > 0 {
            new_limit -= 1;
        } else if valid_limit >= invalid_limit && valid_limit > 0 {
            valid_limit -= 1;
        } else if invalid_limit > 0 {
            invalid_limit -= 1;
        }
    }
    new_limit += batch - (new_limit + valid_limit + invalid_limit);
    (new_limit, valid_limit, invalid_limit)
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
    use super::{deduplicate_parsed_proxies, proxy_row_definition_key, take_matching_proxy};
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
