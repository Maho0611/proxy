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
    let page = load_proxy_list_page(state.clone(), db_query).await?;
    let stats = get_cached_stats(state.clone()).await?;
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
    pub subscription_id: Option<String>,
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
        subscription_id: query.subscription_id.clone(),
        proxy_type: query.proxy_type.clone(),
        quality: query.quality.clone(),
        sort: query.sort.clone(),
        dir: query.dir.clone(),
    }
}

pub async fn load_proxy_list_page(
    state: Arc<AppState>,
    query: ProxyListQuery,
) -> Result<crate::db::ProxyListPage, AppError> {
    let page_state = state.clone();
    let page_query = query.clone();
    let page_future = run_cancellable_db_query(move |cancel_sender| {
        page_state
            .db
            .list_proxy_page_cancellable(&page_query, Some(cancel_sender))
    });

    if query.cursor.is_some() {
        return page_future.await;
    }

    let (mut page, (filtered, total)) =
        tokio::try_join!(page_future, get_proxy_list_counts(state, query))?;
    page.filtered = filtered;
    page.total = total;
    page.total_pages = if filtered == 0 {
        0
    } else {
        filtered.div_ceil(page.page_size)
    };
    page.page = page.page.min(page.total_pages.max(1));
    page.counts_available = true;
    Ok(page)
}

async fn get_proxy_list_counts(
    state: Arc<AppState>,
    query: ProxyListQuery,
) -> Result<(usize, usize), AppError> {
    let total_future =
        get_cached_filtered_proxy_count(state.clone(), ProxyListQuery::default());
    if !proxy_list_query_has_filters(&query) {
        let total = total_future.await?;
        return Ok((total, total));
    }

    let filtered_future = get_cached_filtered_proxy_count(state, query);
    let (total, filtered) = tokio::try_join!(total_future, filtered_future)?;
    Ok((filtered, total))
}

async fn get_cached_filtered_proxy_count(
    state: Arc<AppState>,
    query: ProxyListQuery,
) -> Result<usize, AppError> {
    const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);
    let cache_key = proxy_list_count_cache_key(&query);
    let now = tokio::time::Instant::now();
    if let Some(entry) = state.proxy_list_count_cache.get(&cache_key) {
        if entry.expires_at > now {
            return Ok(entry.filtered);
        }
    }

    let stale_value = state
        .proxy_list_count_cache
        .get(&cache_key)
        .map(|entry| entry.filtered);
    let _singleflight = match state.proxy_list_count_cache_fill.try_lock() {
        Ok(guard) => guard,
        Err(_) if stale_value.is_some() => return Ok(stale_value.unwrap()),
        Err(_) => state.proxy_list_count_cache_fill.lock().await,
    };
    if let Some(entry) = state.proxy_list_count_cache.get(&cache_key) {
        if entry.expires_at > tokio::time::Instant::now() {
            return Ok(entry.filtered);
        }
    }

    let query_state = state.clone();
    let count_result = run_cancellable_db_query(move |cancel_sender| {
        query_state
            .db
            .count_proxy_list_cancellable(&query, Some(cancel_sender))
    })
    .await;
    let filtered = match count_result {
        Ok(filtered) => filtered,
        Err(error) => {
            if let Some(filtered) = stale_value {
                tracing::warn!("Filtered proxy count refresh failed, serving stale cache: {error}");
                return Ok(filtered);
            }
            return Err(error);
        }
    };
    state.proxy_list_count_cache.insert(
        cache_key,
        crate::ProxyListCountCacheEntry {
            filtered,
            expires_at: tokio::time::Instant::now() + CACHE_TTL,
        },
    );
    Ok(filtered)
}

fn proxy_list_query_has_filters(query: &ProxyListQuery) -> bool {
    query.unique_exit_ip
        || query.search.as_deref().is_some_and(|value| !value.trim().is_empty())
        || query.status.as_deref().is_some_and(|value| !value.trim().is_empty())
        || query
            .subscription_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || query
            .proxy_type
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || query.quality.as_deref().is_some_and(|value| !value.trim().is_empty())
}

fn proxy_list_count_cache_key(query: &ProxyListQuery) -> String {
    serde_json::json!({
        "unique_exit_ip": query.unique_exit_ip,
        "search": query.search.as_deref().map(str::trim).filter(|value| !value.is_empty()),
        "status": query.status.as_deref().map(str::trim).filter(|value| !value.is_empty()),
        "subscription_id": query.subscription_id.as_deref().map(str::trim).filter(|value| !value.is_empty()),
        "proxy_type": query.proxy_type.as_deref().map(str::trim).filter(|value| !value.is_empty()),
        "quality": query.quality.as_deref().map(str::trim).filter(|value| !value.is_empty()),
    })
    .to_string()
}

struct PostgresCancelGuard(Option<postgres::CancelToken>);

impl PostgresCancelGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for PostgresCancelGuard {
    fn drop(&mut self) {
        let Some(cancel_token) = self.0.take() else {
            return;
        };
        std::thread::spawn(move || {
            if let Err(error) = cancel_token.cancel_query(postgres::NoTls) {
                tracing::debug!("Failed to cancel abandoned PostgreSQL query: {error}");
            }
        });
    }
}

async fn run_cancellable_db_query<T, F>(query: F) -> Result<T, AppError>
where
    T: Send + 'static,
    F: FnOnce(
            tokio::sync::oneshot::Sender<postgres::CancelToken>,
        ) -> Result<T, postgres::Error>
        + Send
        + 'static,
{
    let (cancel_sender, cancel_receiver) = tokio::sync::oneshot::channel();
    let task = tokio::task::spawn_blocking(move || query(cancel_sender));
    let mut cancel_guard = PostgresCancelGuard(cancel_receiver.await.ok());
    let result = task
        .await
        .map_err(|error| AppError::Internal(format!("Proxy list task failed: {error}")))?;
    cancel_guard.disarm();
    result.map_err(AppError::from)
}

pub async fn get_cached_stats(state: Arc<AppState>) -> Result<serde_json::Value, AppError> {
    if let Some(entry) = state.dashboard_stats_cache.get(&()) {
        return Ok(entry.value.clone());
    }
    invalidate_stats_cache(state.as_ref());
    Ok(empty_dashboard_stats())
}

pub fn empty_dashboard_stats() -> serde_json::Value {
    json!({
        "total_proxies": 0,
        "valid_proxies": 0,
        "untested_proxies": 0,
        "invalid_proxies": 0,
        "subscriptions": 0,
        "quality_checked": 0,
        "chatgpt_accessible": 0,
        "google_accessible": 0,
        "residential": 0,
        "by_type": {},
        "by_country": {},
        "normalization_integrity": {
            "health_missing": 0,
            "runtime_missing": 0,
            "unreferenced_definitions": 0,
            "retry_with_exit": 0,
        },
    })
}

pub fn invalidate_stats_cache(state: &AppState) {
    // Preserve the last-good values while a single background worker merges
    // bursts of mutations into one refresh.
    if !state
        .stats_refresh_pending
        .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        state.stats_refresh_notify.notify_one();
    }
    state.proxy_list_count_cache.clear();
    state.subscription_duplicate_generation.fetch_add(
        1,
        std::sync::atomic::Ordering::AcqRel,
    );
    state.subscription_duplicate_cache.clear();
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
    let snapshot = state.selection_snapshot.load();
    Ok(snapshot.pick(filter, count, state))
}
