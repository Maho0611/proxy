use crate::api::fetch::{
    find_proxy_snapshot, list_query_to_db, proxy_list_item_to_json, ListProxyQuery,
};
use crate::error::AppError;
use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use serde_json::json;
use std::sync::Arc;

pub async fn list_proxies(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListProxyQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let page = crate::api::fetch::load_proxy_list_page(
        state.clone(),
        list_query_to_db(&query),
    )
    .await?;
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
    })))
}

pub async fn delete_proxy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let proxy = find_proxy_snapshot(&state, &id)?;
    if let Some(proxy) = &proxy {
        crate::bindings::cleanup_proxy_binding(&state, &proxy.id, proxy.local_port).await;
    }

    state.binding_usage.remove(&id);
    state.pool.remove(&id);
    state.db.delete_proxy(&id)?;
    crate::selection::rebuild(state.as_ref())?;
    crate::api::fetch::invalidate_stats_cache(state.as_ref());
    crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
    Ok(Json(json!({ "message": "Proxy deleted" })))
}

pub async fn cleanup_proxies(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let threshold = state.config.validation.error_threshold;

    // Remove bindings before deleting DB rows so sing-box listeners do not leak.
    let targets: Vec<_> = state
        .pool
        .get_all()
        .into_iter()
        .filter(|proxy| proxy.error_count >= threshold)
        .collect();
    for proxy in &targets {
        crate::bindings::cleanup_proxy_binding(&state, &proxy.id, proxy.local_port).await;
    }

    let count = state.db.cleanup_high_error_proxies(threshold)?;

    // Remove from pool too
    for proxy in &targets {
        state.binding_usage.remove(&proxy.id);
        state.pool.remove(&proxy.id);
    }
    if count > 0 {
        crate::selection::rebuild(state.as_ref())?;
        crate::api::fetch::invalidate_stats_cache(state.as_ref());
        crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
    }

    Ok(Json(json!({
        "message": format!("Cleaned up {count} proxies"),
        "removed": count,
    })))
}

pub async fn trigger_validation(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !crate::pool::validator::start_validation(state) {
        return Ok(Json(json!({
            "message": "Validation already running"
        })));
    }

    Ok(Json(json!({
        "message": "Validation started in background"
    })))
}

pub async fn trigger_quality_check(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !crate::quality::checker::start_quality_check(state) {
        return Ok(Json(json!({
            "message": "Quality check already running"
        })));
    }

    Ok(Json(json!({
        "message": "Quality check started in background"
    })))
}

pub async fn get_job_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({
        "validation": state.validation_progress.snapshot(),
        "quality_check": state.quality_progress.snapshot(),
    }))
}

pub async fn ping() -> Json<serde_json::Value> {
    Json(json!({ "ok": true }))
}

pub async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut stats = crate::api::fetch::get_cached_stats(state.clone()).await?;
    if let Some(object) = stats.as_object_mut() {
        object.insert(
            "database_runtime".into(),
            serde_json::to_value(state.db.runtime_metrics()).unwrap_or_default(),
        );
    }
    Ok(Json(stats))
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let users = state.db.get_all_users()?;
    let total = users.len();
    Ok(Json(json!({
        "users": users,
        "total": total,
    })))
}

pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(account) = state.db.get_proxy_account_for_owner(&id)? {
        state.db.delete_proxy_account(&account.id)?;
        state.proxy_accounts.remove(&account.username);
        state.proxy_account_last_used.remove(&account.id);
        crate::proxy_rotation::remove_principal_sessions(&state, &account.id);
    }
    state.db.delete_user(&id)?;
    Ok(Json(json!({ "message": "User deleted" })))
}

pub async fn ban_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    set_owned_proxy_account_enabled(&state, &id, false)?;
    state.db.set_user_banned(&id, true)?;
    Ok(Json(json!({ "message": "User banned" })))
}

pub async fn unban_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.set_user_banned(&id, false)?;
    set_owned_proxy_account_enabled(&state, &id, true)?;
    Ok(Json(json!({ "message": "User unbanned" })))
}

fn set_owned_proxy_account_enabled(
    state: &AppState,
    user_id: &str,
    enabled: bool,
) -> Result<(), AppError> {
    let Some(existing) = state.db.get_proxy_account_for_owner(user_id)? else {
        return Ok(());
    };
    let account = state
        .db
        .update_proxy_account(&existing.id, None, false, None, Some(enabled))?
        .ok_or_else(|| AppError::NotFound("Proxy account not found".into()))?;
    state
        .proxy_accounts
        .insert(account.username.clone(), account.clone());
    if !enabled {
        crate::proxy_rotation::remove_principal_sessions(state, &account.id);
    }
    Ok(())
}
