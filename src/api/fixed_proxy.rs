use crate::api::{auth, proxy_access};
use crate::db::{FixedProxySlot, ProxyAccount, User};
use crate::error::AppError;
use crate::pool::manager::{PoolProxy, ProxyFilter};
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use postgres::error::SqlState;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct AllocateFixedExits {
    pub count: usize,
    pub country: String,
    #[serde(rename = "type")]
    pub proxy_type: Option<String>,
    #[serde(default)]
    pub residential: bool,
    #[serde(default)]
    pub chatgpt: bool,
    #[serde(default)]
    pub google: bool,
}

#[derive(Debug, Deserialize)]
pub struct PinFixedExits {
    pub proxy_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFixedExit {
    pub label: Option<String>,
    pub included_in_subscription: Option<bool>,
}

pub async fn get_fixed_exits(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, account) = authenticated_account(&state, &headers).await?;
    crate::fixed_proxy::reconcile_account(&state, &account.id).await;
    fixed_access_response(&state, &account)
}

pub async fn allocate_fixed_exits(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AllocateFixedExits>,
) -> Result<Response, AppError> {
    let (_, account) = authenticated_account(&state, &headers).await?;
    if body.count == 0 || body.count > crate::fixed_proxy::MAX_SLOTS_PER_ACCOUNT {
        return Err(AppError::BadRequest(format!(
            "count must be between 1 and {}",
            crate::fixed_proxy::MAX_SLOTS_PER_ACCOUNT
        )));
    }
    let country = normalize_country(&body.country)?;
    let proxy_type = normalize_proxy_type(body.proxy_type.as_deref());
    let account_lock = crate::fixed_proxy::slot_lock(&state, &format!("account:{}", account.id));
    let _guard = account_lock.lock().await;
    let existing = state.db.get_fixed_proxy_slots(&account.id)?;
    if existing.len() + body.count > crate::fixed_proxy::MAX_SLOTS_PER_ACCOUNT {
        return Err(AppError::BadRequest(format!(
            "an account can keep at most {} fixed exits",
            crate::fixed_proxy::MAX_SLOTS_PER_ACCOUNT
        )));
    }

    let filter = ProxyFilter {
        country: Some(country.clone()),
        proxy_type: proxy_type.clone(),
        residential: body.residential,
        chatgpt: body.chatgpt,
        google: body.google,
        ..ProxyFilter::default()
    };
    let candidates = crate::fixed_proxy::allocation_candidates(&state, &account.id, &filter)
        .map_err(AppError::BadRequest)?;
    if candidates.len() < body.count {
        return Err(AppError::BadRequest(format!(
            "only {} distinct valid exits currently match the requested region and filters",
            candidates.len()
        )));
    }
    let now = chrono::Utc::now().to_rfc3339();
    let slots: Vec<FixedProxySlot> = candidates
        .into_iter()
        .take(body.count)
        .enumerate()
        .map(|(index, proxy)| {
            new_slot(
                &account,
                &proxy,
                format!("{} 固定出口 {:02}", country, existing.len() + index + 1),
                country.clone(),
                proxy_type.clone(),
                body.residential,
                body.chatgpt,
                body.google,
                &now,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    state
        .db
        .insert_fixed_proxy_slots(&slots)
        .map_err(map_fixed_write_error)?;
    fixed_access_response(&state, &account)
}

pub async fn pin_fixed_exits(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PinFixedExits>,
) -> Result<Response, AppError> {
    let (_, account) = authenticated_account(&state, &headers).await?;
    if body.proxy_ids.is_empty() || body.proxy_ids.len() > crate::fixed_proxy::MAX_SLOTS_PER_ACCOUNT
    {
        return Err(AppError::BadRequest(format!(
            "proxy_ids must contain between 1 and {} entries",
            crate::fixed_proxy::MAX_SLOTS_PER_ACCOUNT
        )));
    }
    let unique_ids: HashSet<&str> = body.proxy_ids.iter().map(String::as_str).collect();
    if unique_ids.len() != body.proxy_ids.len() {
        return Err(AppError::BadRequest("proxy_ids contains duplicates".into()));
    }

    let account_lock = crate::fixed_proxy::slot_lock(&state, &format!("account:{}", account.id));
    let _guard = account_lock.lock().await;
    let existing = state.db.get_fixed_proxy_slots(&account.id)?;
    if existing.len() + body.proxy_ids.len() > crate::fixed_proxy::MAX_SLOTS_PER_ACCOUNT {
        return Err(AppError::BadRequest(format!(
            "an account can keep at most {} fixed exits",
            crate::fixed_proxy::MAX_SLOTS_PER_ACCOUNT
        )));
    }
    let mut used_ips: HashSet<String> = existing.iter().map(|slot| slot.exit_ip.clone()).collect();
    let now = chrono::Utc::now().to_rfc3339();
    let mut slots = Vec::with_capacity(body.proxy_ids.len());
    for (index, proxy_id) in body.proxy_ids.iter().enumerate() {
        let (row, quality) = state
            .db
            .get_proxy_record(proxy_id)?
            .ok_or_else(|| AppError::NotFound(format!("proxy {proxy_id} not found")))?;
        if !row.is_valid || row.orphaned_at.is_some() {
            return Err(AppError::BadRequest(format!(
                "proxy {proxy_id} is not a current valid exit"
            )));
        }
        let quality = quality.ok_or_else(|| {
            AppError::BadRequest(format!("proxy {proxy_id} has no quality metadata"))
        })?;
        let exit_ip = quality
            .ip_address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::BadRequest(format!("proxy {proxy_id} has no exit IP")))?;
        let country = quality
            .country
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_uppercase)
            .ok_or_else(|| AppError::BadRequest(format!("proxy {proxy_id} has no country")))?;
        if !used_ips.insert(exit_ip.to_string()) {
            return Err(AppError::BadRequest(format!(
                "exit IP {exit_ip} is already pinned by this account"
            )));
        }
        let proxy = crate::pool::manager::ProxyPool::from_db_parts(row, Some(quality));
        slots.push(new_slot(
            &account,
            &proxy,
            format!("{} 固定出口 {:02}", country, existing.len() + index + 1),
            country,
            None,
            false,
            false,
            false,
            &now,
        )?);
    }
    state
        .db
        .insert_fixed_proxy_slots(&slots)
        .map_err(map_fixed_write_error)?;
    fixed_access_response(&state, &account)
}

pub async fn update_fixed_exit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateFixedExit>,
) -> Result<Response, AppError> {
    let (_, account) = authenticated_account(&state, &headers).await?;
    let label = body.label.as_deref().map(validate_label).transpose()?;
    state
        .db
        .update_fixed_proxy_slot_settings(
            &account.id,
            &id,
            label.as_deref(),
            body.included_in_subscription,
        )?
        .ok_or_else(|| AppError::NotFound("fixed exit slot not found".into()))?;
    fixed_access_response(&state, &account)
}

pub async fn replace_fixed_exit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let (_, account) = authenticated_account(&state, &headers).await?;
    crate::fixed_proxy::force_replace_slot(&state, &account.id, &id, "manual")
        .await
        .map_err(AppError::BadRequest)?;
    fixed_access_response(&state, &account)
}

pub async fn delete_fixed_exit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let (_, account) = authenticated_account(&state, &headers).await?;
    if !state.db.delete_fixed_proxy_slot(&account.id, &id)? {
        return Err(AppError::NotFound("fixed exit slot not found".into()));
    }
    state.fixed_proxy_slot_locks.remove(&id);
    fixed_access_response(&state, &account)
}

pub async fn rotate_fixed_subscription_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, account) = authenticated_account(&state, &headers).await?;
    state.db.rotate_fixed_subscription_version(&account.id)?;
    fixed_access_response(&state, &account)
}

pub async fn export_fixed_subscription(
    State(state): State<Arc<AppState>>,
    Path((account_id, token, format)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    proxy_access::ensure_credentials_configured(&state)?;
    let account = state
        .db
        .get_proxy_account_by_id(&account_id)?
        .filter(|account| account.enabled)
        .ok_or_else(|| AppError::Unauthorized("invalid fixed subscription".into()))?;
    let version = state
        .db
        .get_or_create_fixed_subscription_version(&account.id)?;
    if !crate::proxy_account::verify_fixed_subscription_token(
        &state.config.proxy_access.credential_secret,
        &account.id,
        version,
        &token,
    ) {
        return Err(AppError::Unauthorized("invalid fixed subscription".into()));
    }
    let slots: Vec<FixedProxySlot> = state
        .db
        .get_fixed_proxy_slots(&account.id)?
        .into_iter()
        .filter(|slot| slot.included_in_subscription)
        .collect();
    let password = crate::proxy_account::derive_password(
        &state.config.proxy_access.credential_secret,
        &account.id,
        account.credential_version,
    );
    let (body, content_type) =
        build_subscription_body(&state, &account, &password, &slots, &format)?;
    let mut response = (StatusCode::OK, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    if let Ok(value) = HeaderValue::from_str(&slots.len().to_string()) {
        response.headers_mut().insert("x-proxy-count", value);
    }
    Ok(response)
}

async fn authenticated_account(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(User, ProxyAccount), AppError> {
    proxy_access::ensure_credentials_configured(state)?;
    let user = auth::authenticate_request(state, headers, None).await?;
    let account = proxy_access::get_or_create_user_account(state, &user)?;
    if !account.enabled {
        return Err(AppError::Unauthorized("proxy account is disabled".into()));
    }
    Ok((user, account))
}

fn normalize_country(value: &str) -> Result<String, AppError> {
    let country = value.trim().to_ascii_uppercase();
    if !crate::fixed_proxy::valid_country(&country) {
        return Err(AppError::BadRequest(
            "country must contain 2 to 8 letters or digits".into(),
        ));
    }
    Ok(country)
}

fn normalize_proxy_type(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[allow(clippy::too_many_arguments)]
fn new_slot(
    account: &ProxyAccount,
    proxy: &PoolProxy,
    label: String,
    country: String,
    proxy_type: Option<String>,
    residential: bool,
    chatgpt: bool,
    google: bool,
    now: &str,
) -> Result<FixedProxySlot, AppError> {
    let exit_ip = crate::fixed_proxy::candidate_exit_ip(proxy)
        .ok_or_else(|| AppError::BadRequest("selected proxy has no exit IP".into()))?;
    Ok(FixedProxySlot {
        id: uuid::Uuid::new_v4().to_string(),
        account_id: account.id.clone(),
        slot_key: crate::fixed_proxy::new_slot_key(),
        label,
        country,
        proxy_type,
        residential,
        chatgpt,
        google,
        proxy_id: proxy.id.clone(),
        exit_ip,
        included_in_subscription: true,
        replacement_count: 0,
        last_replacement_reason: None,
        last_replaced_at: None,
        created_at: now.to_string(),
        updated_at: now.to_string(),
    })
}

fn validate_label(value: &str) -> Result<String, AppError> {
    let label = value.trim();
    if label.is_empty() || label.chars().count() > 80 {
        return Err(AppError::BadRequest(
            "label must contain between 1 and 80 characters".into(),
        ));
    }
    Ok(label.to_string())
}

fn map_fixed_write_error(error: postgres::Error) -> AppError {
    if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
        AppError::BadRequest("a selected exit or slot is already assigned".into())
    } else {
        AppError::Internal(format!("database error: {error}"))
    }
}

fn fixed_access_response(state: &AppState, account: &ProxyAccount) -> Result<Response, AppError> {
    let version = state
        .db
        .get_or_create_fixed_subscription_version(&account.id)?;
    let token = crate::proxy_account::derive_fixed_subscription_token(
        &state.config.proxy_access.credential_secret,
        &account.id,
        version,
    );
    let base_path = format!("/fixed-sub/{}/{}", account.id, token);
    let slots = state
        .db
        .get_fixed_proxy_slots(&account.id)?
        .iter()
        .map(|slot| slot_json(state, account, slot))
        .collect::<Vec<_>>();
    let mut response = Json(json!({
        "gateway": proxy_access::gateway_json(state),
        "account": account,
        "max_slots": crate::fixed_proxy::MAX_SLOTS_PER_ACCOUNT,
        "slots": slots,
        "subscriptions": {
            "clash_http": format!("{base_path}/clash-http.yaml"),
            "clash_socks5": format!("{base_path}/clash-socks5.yaml"),
            "http_urls": format!("{base_path}/http.txt"),
            "socks5_urls": format!("{base_path}/socks5.txt"),
        }
    }))
    .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    Ok(response)
}

fn slot_json(state: &AppState, account: &ProxyAccount, slot: &FixedProxySlot) -> Value {
    let health = crate::fixed_proxy::current_slot_proxy(state, slot);
    let (status, status_reason, proxy_name, current_type) = match health {
        Ok(proxy) => ("active", None, Some(proxy.name), Some(proxy.proxy_type)),
        Err(reason) => {
            let public_reason = if reason.starts_with("database lookup failed:") {
                "database_lookup_failed".to_string()
            } else {
                reason
            };
            ("unavailable", Some(public_reason), None, None)
        }
    };
    json!({
        "id": slot.id,
        "slot_key": slot.slot_key,
        "label": slot.label,
        "country": slot.country,
        "proxy_id": slot.proxy_id,
        "exit_ip": slot.exit_ip,
        "username": format!("{}-fixed-{}", account.username, slot.slot_key),
        "status": status,
        "status_reason": status_reason,
        "proxy_name": proxy_name,
        "current_type": current_type,
        "replacement_filters": {
            "type": slot.proxy_type,
            "residential": slot.residential,
            "chatgpt": slot.chatgpt,
            "google": slot.google,
        },
        "included_in_subscription": slot.included_in_subscription,
        "replacement_count": slot.replacement_count,
        "last_replacement_reason": slot.last_replacement_reason,
        "last_replaced_at": slot.last_replaced_at,
        "created_at": slot.created_at,
        "updated_at": slot.updated_at,
    })
}

fn build_subscription_body(
    state: &AppState,
    account: &ProxyAccount,
    password: &str,
    slots: &[FixedProxySlot],
    format: &str,
) -> Result<(String, &'static str), AppError> {
    let host = state.config.proxy_access.public_host.trim();
    let port = state.config.proxy_access.public_port;
    if host.is_empty() || port == 0 {
        return Err(AppError::BadRequest(
            "public proxy gateway is not configured".into(),
        ));
    }
    match format {
        "clash-http.yaml" => Ok((
            build_clash_fixed_subscription(host, port, account, password, slots, "http")?,
            "application/x-yaml; charset=utf-8",
        )),
        "clash-socks5.yaml" => Ok((
            build_clash_fixed_subscription(host, port, account, password, slots, "socks5")?,
            "application/x-yaml; charset=utf-8",
        )),
        "http.txt" => Ok((
            build_url_list(host, port, account, password, slots, "http"),
            "text/plain; charset=utf-8",
        )),
        "socks5.txt" => Ok((
            build_url_list(host, port, account, password, slots, "socks5"),
            "text/plain; charset=utf-8",
        )),
        _ => Err(AppError::NotFound(
            "unsupported fixed subscription format".into(),
        )),
    }
}

fn build_clash_fixed_subscription(
    host: &str,
    port: u16,
    account: &ProxyAccount,
    password: &str,
    slots: &[FixedProxySlot],
    proxy_type: &str,
) -> Result<String, AppError> {
    let proxies = slots
        .iter()
        .enumerate()
        .map(|(index, slot)| {
            let mut proxy = Map::new();
            proxy.insert(
                "name".into(),
                Value::String(format!(
                    "{} · {} · {:02}",
                    slot.label,
                    slot.exit_ip,
                    index + 1
                )),
            );
            proxy.insert("type".into(), Value::String(proxy_type.to_string()));
            proxy.insert("server".into(), Value::String(host.to_string()));
            proxy.insert("port".into(), Value::Number(port.into()));
            proxy.insert(
                "username".into(),
                Value::String(format!("{}-fixed-{}", account.username, slot.slot_key)),
            );
            proxy.insert("password".into(), Value::String(password.to_string()));
            Value::Object(proxy)
        })
        .collect::<Vec<_>>();
    serde_yaml::to_string(&json!({ "proxies": proxies }))
        .map_err(|error| AppError::Internal(format!("failed to build subscription: {error}")))
}

fn build_url_list(
    host: &str,
    port: u16,
    account: &ProxyAccount,
    password: &str,
    slots: &[FixedProxySlot],
    scheme: &str,
) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let password = utf8_percent_encode(password, NON_ALPHANUMERIC).to_string();
    slots
        .iter()
        .map(|slot| {
            let username = format!("{}-fixed-{}", account.username, slot.slot_key);
            let username = utf8_percent_encode(&username, NON_ALPHANUMERIC);
            format!("{scheme}://{username}:{password}@{host}:{port}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> ProxyAccount {
        ProxyAccount {
            id: "account".into(),
            label: "test".into(),
            username: "zp_test".into(),
            owner_user_id: Some("user".into()),
            enabled: true,
            credential_version: 1,
            last_used_at: None,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    fn slot(key: &str, ip: &str) -> FixedProxySlot {
        FixedProxySlot {
            id: key.into(),
            account_id: "account".into(),
            slot_key: key.into(),
            label: "US fixed".into(),
            country: "US".into(),
            proxy_type: None,
            residential: false,
            chatgpt: false,
            google: false,
            proxy_id: "proxy".into(),
            exit_ip: ip.into(),
            included_in_subscription: true,
            replacement_count: 0,
            last_replacement_reason: None,
            last_replaced_at: None,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    #[test]
    fn text_subscription_uses_one_gateway_and_distinct_slot_usernames() {
        let body = build_url_list(
            "proxy.example.com",
            50089,
            &account(),
            "secret",
            &[slot("one", "1.1.1.1"), slot("two", "2.2.2.2")],
            "http",
        );
        assert_eq!(body.lines().count(), 2);
        assert!(body.contains("zp%5Ftest%2Dfixed%2Done"));
        assert!(body.contains("zp%5Ftest%2Dfixed%2Dtwo"));
        assert!(body
            .lines()
            .all(|line| line.contains("proxy.example.com:50089")));
    }

    #[test]
    fn clash_subscription_contains_gateway_nodes_only() {
        let body = build_clash_fixed_subscription(
            "proxy.example.com",
            50089,
            &account(),
            "secret",
            &[slot("one", "1.1.1.1")],
            "socks5",
        )
        .unwrap();
        assert!(body.contains("server: proxy.example.com"));
        assert!(body.contains("type: socks5"));
        assert!(body.contains("zp_test-fixed-one"));
        assert!(!body.contains("1.1.1.1\n  port"));
    }
}
