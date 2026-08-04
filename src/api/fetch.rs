use crate::api::auth;
use crate::db::ProxyListQuery;
use crate::error::AppError;
use crate::pool::manager::ProxyFilter;
use crate::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

const RELAY_FAILURE_COOLDOWN_SECS: i64 = 300;

#[derive(Debug, Deserialize)]
pub struct FetchQuery {
    pub api_key: Option<String>,
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
    pub count: Option<usize>,
    pub proxy_id: Option<String>,
}

pub async fn fetch_proxies(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<FetchQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth::authenticate_request(&state, &headers, query.api_key.as_deref()).await?;

    let filter = ProxyFilter {
        chatgpt: query.chatgpt,
        google: query.google,
        residential: query.residential,
        risk_max: query.risk_max,
        country: query.country,
        proxy_type: query.proxy_type,
        count: query.count,
        proxy_id: query.proxy_id,
    };
    let count = filter.count.unwrap_or(1);

    if let Some(ref id) = filter.proxy_id {
        if let Some(proxy) = find_proxy_snapshot(&state, id)? {
            return Ok(Json(json!({
                "proxies": [proxy_to_json(&proxy)]
            })));
        } else {
            return Err(AppError::NotFound(format!("Proxy {id} not found")));
        }
    }

    let proxies = pick_random_valid_proxies(&state, &filter, count)?;
    if proxies.is_empty() {
        return Ok(Json(json!({
            "proxies": [],
            "message": "No proxies match the given filters"
        })));
    }

    let proxy_list: Vec<serde_json::Value> = proxies.iter().map(proxy_to_json).collect();

    Ok(Json(json!({
        "proxies": proxy_list,
        "count": proxy_list.len(),
    })))
}

/// User-accessible proxy list with full quality details
pub async fn list_all_proxies(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ListProxyQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth::authenticate_request(&state, &headers, query.api_key.as_deref()).await?;

    let mut db_query = list_query_to_db(&query);
    db_query.unique_exit_ip = true;
    let page = state.db.list_proxy_page(&db_query)?;
    let stats = get_cached_stats(state.as_ref())?;
    let stale_hours = state.config.quality.stale_hours.max(1);
    let proxy_list: Vec<serde_json::Value> = page
        .proxies
        .iter()
        .map(|proxy| proxy_list_item_to_json(proxy, stale_hours))
        .collect();

    Ok(Json(json!({
        "proxies": proxy_list,
        "total": page.counts_available.then_some(page.total),
        "filtered": page.counts_available.then_some(page.filtered),
        "page": page.page,
        "page_size": page.page_size,
        "total_pages": page.counts_available.then_some(page.total_pages),
        "next_cursor": page.next_cursor,
        "prev_cursor": page.prev_cursor,
        "has_next": page.has_next,
        "has_previous": page.has_previous,
        "valid": stats["valid_proxies"],
        "untested": stats["untested_proxies"],
        "invalid": stats["invalid_proxies"],
        "quality_checked": stats["quality_checked"],
        "chatgpt_accessible": stats["chatgpt_accessible"],
        "google_accessible": stats["google_accessible"],
        "residential": stats["residential"],
    })))
}

#[derive(Debug, Deserialize, Default)]
pub struct ListProxyQuery {
    pub api_key: Option<String>,
    pub page: Option<usize>,
    pub page_size: Option<usize>,
    pub cursor: Option<String>,
    pub direction: Option<String>,
    pub search: Option<String>,
    pub status: Option<String>,
    #[serde(rename = "type")]
    pub proxy_type: Option<String>,
    pub quality: Option<String>,
    pub sort: Option<String>,
    pub dir: Option<String>,
}

fn proxy_to_json(p: &crate::pool::manager::PoolProxy) -> serde_json::Value {
    json!({
        "id": p.id,
        "name": p.name,
        "type": p.proxy_type,
        "server": p.server,
        "port": p.port,
        "local_port": p.local_port,
        "status": p.status,
        "error_count": p.error_count,
        "quality": p.quality.as_ref().map(|q| json!({
            "ip_address": q.ip_address,
            "country": q.country,
            "ip_type": q.ip_type,
            "is_residential": q.is_residential,
            "chatgpt": q.chatgpt_accessible,
            "google": q.google_accessible,
            "risk_score": q.risk_score,
            "risk_level": q.risk_level,
            "checked_at": q.checked_at,
            "details": q.details,
        })),
    })
}

pub fn proxy_list_item_to_json(
    p: &crate::db::ProxyListItem,
    stale_hours: u64,
) -> serde_json::Value {
    let now = chrono::Utc::now();
    json!({
        "id": p.id,
        "subscription_id": p.subscription_id,
        "name": p.name,
        "type": p.proxy_type,
        "server": p.server,
        "port": p.port,
        "local_port": p.local_port,
        "status": p.status,
        "error_count": p.error_count,
        "quality": p.quality.as_ref().map(|q| json!({
            "ip_address": q.ip_address,
            "country": q.country,
            "ip_type": q.ip_type,
            "is_residential": q.is_residential,
            "chatgpt": q.chatgpt_accessible,
            "google": q.google_accessible,
            "risk_score": q.risk_score,
            "risk_level": q.risk_level,
            "checked_at": q.checked_at,
            "details": q.extra_json.as_deref().and_then(|raw| {
                serde_json::from_str::<serde_json::Value>(raw).ok()
            }),
            "stale": crate::quality::checker::quality_checked_at_is_stale(
                Some(q.checked_at.as_str()),
                &now,
                stale_hours,
            ),
        })),
    })
}

pub fn list_query_to_db(query: &ListProxyQuery) -> ProxyListQuery {
    ProxyListQuery {
        page: query.page.unwrap_or(1),
        page_size: query.page_size.unwrap_or(50),
        unique_exit_ip: false,
        cursor: query.cursor.clone(),
        direction: query.direction.clone(),
        search: query.search.clone(),
        status: query.status.clone(),
        proxy_type: query.proxy_type.clone(),
        quality: query.quality.clone(),
        sort: query.sort.clone(),
        dir: query.dir.clone(),
    }
}

pub fn get_cached_stats(state: &AppState) -> Result<serde_json::Value, AppError> {
    if let Some(entry) = state.dashboard_stats_cache.get(&()) {
        if entry.expires_at > tokio::time::Instant::now() {
            return Ok(entry.value.clone());
        }
    }

    let value = state.db.get_stats()?;
    state.dashboard_stats_cache.insert(
        (),
        crate::DashboardStatsCacheEntry {
            value: value.clone(),
            expires_at: tokio::time::Instant::now() + std::time::Duration::from_secs(15),
        },
    );
    Ok(value)
}

pub fn invalidate_stats_cache(state: &AppState) {
    state.dashboard_stats_cache.clear();
}

pub fn find_proxy_snapshot(
    state: &AppState,
    id: &str,
) -> Result<Option<crate::pool::manager::PoolProxy>, AppError> {
    if let Some(proxy) = state.pool.get(id) {
        return Ok(Some(proxy));
    }

    let record = state.db.get_proxy_record(id)?;
    Ok(record.map(|(row, quality)| crate::pool::manager::ProxyPool::from_db_parts(row, quality)))
}

pub fn pick_random_valid_proxies(
    state: &AppState,
    filter: &ProxyFilter,
    count: usize,
) -> Result<Vec<crate::pool::manager::PoolProxy>, AppError> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let recent_error_before = if RELAY_FAILURE_COOLDOWN_SECS > 0 {
        Some(
            (chrono::Utc::now() - chrono::Duration::seconds(RELAY_FAILURE_COOLDOWN_SECS))
                .to_rfc3339(),
        )
    } else {
        None
    };

    let records =
        state
            .db
            .get_random_valid_proxy_records(filter, count, recent_error_before.as_deref())?;
    Ok(records
        .into_iter()
        .map(|(row, quality)| crate::pool::manager::ProxyPool::from_db_parts(row, quality))
        .collect())
}
