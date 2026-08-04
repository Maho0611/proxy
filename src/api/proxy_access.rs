use crate::api::auth::extract_session_user;
use crate::db::{ProxyAccount, User};
use crate::error::AppError;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use postgres::error::SqlState;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct CreateProxyAccount {
    pub label: String,
    pub username: String,
    pub owner_user_id: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProxyAccount {
    pub label: Option<String>,
    pub owner_user_id: Option<String>,
    pub clear_owner: Option<bool>,
    pub enabled: Option<bool>,
}

pub async fn get_user_access(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = extract_session_user(&state, &headers).await?;
    let account = if state.config.proxy_access.accounts_enabled() {
        Some(get_or_create_user_account(&state, &user)?)
    } else {
        state.db.get_proxy_account_for_owner(&user.id)?
    };
    let stats = crate::api::fetch::get_cached_stats(state.as_ref())?;
    Ok(Json(json!({
        "gateway": gateway_json(&state),
        "account": account,
        "filters": filter_metadata(&stats),
        "rotation_mode": "new_tcp_connection",
        "rotation_modes": {
            "per_connection": {
                "enabled": true,
                "username_suffix": null,
            },
            "timed": {
                "enabled": true,
                "username_suffix": "session-{id}-rotate-{seconds}",
                "min_interval_secs": crate::proxy_rotation::MIN_INTERVAL_SECS,
                "max_interval_secs": crate::proxy_rotation::MAX_INTERVAL_SECS,
                "max_session_id_length": crate::proxy_rotation::MAX_SESSION_ID_LEN,
            }
        },
    })))
}

pub async fn reveal_user_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    ensure_credentials_configured(&state)?;
    let user = extract_session_user(&state, &headers).await?;
    let account = get_or_create_user_account(&state, &user)?;
    Ok(no_store_credential_response(&state, &account))
}

pub async fn rotate_user_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    ensure_credentials_configured(&state)?;
    let user = extract_session_user(&state, &headers).await?;
    let existing = get_or_create_user_account(&state, &user)?;
    let account = state
        .db
        .rotate_proxy_account(&existing.id)?
        .ok_or_else(|| AppError::NotFound("Proxy account not found".into()))?;
    state
        .proxy_accounts
        .insert(account.username.clone(), account.clone());
    Ok(no_store_credential_response(&state, &account))
}

pub async fn list_admin_accounts(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(json!({
        "accounts": state.db.get_proxy_accounts()?,
        "gateway": gateway_json(&state),
        "auth_mode": state.config.proxy_access.auth_mode,
    })))
}

pub async fn create_admin_account(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateProxyAccount>,
) -> Result<Response, AppError> {
    ensure_credentials_configured(&state)?;
    let label = validate_label(&body.label)?;
    let username = body.username.trim().to_string();
    if !crate::proxy_account::validate_username(&username) {
        return Err(AppError::BadRequest(
            "Username must match [A-Za-z0-9_]{3,32}".into(),
        ));
    }
    if state
        .config
        .proxy_listener
        .iter()
        .any(|listener| listener.username == username)
    {
        return Err(AppError::BadRequest(
            "Username conflicts with a configured static listener account".into(),
        ));
    }
    if state.proxy_accounts.contains_key(&username) {
        return Err(AppError::BadRequest("Username already exists".into()));
    }

    let owner_user_id = normalize_owner(body.owner_user_id.as_deref());
    validate_owner(&state, owner_user_id.as_deref(), None)?;
    let now = chrono::Utc::now().to_rfc3339();
    let account = ProxyAccount {
        id: uuid::Uuid::new_v4().to_string(),
        label,
        username,
        owner_user_id,
        enabled: body.enabled.unwrap_or(true),
        credential_version: 1,
        last_used_at: None,
        created_at: now.clone(),
        updated_at: now,
    };
    if let Err(error) = state.db.insert_proxy_account(&account) {
        return Err(map_account_write_error(error));
    }
    state
        .proxy_accounts
        .insert(account.username.clone(), account.clone());
    Ok(no_store_credential_response(&state, &account))
}

pub async fn update_admin_account(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<UpdateProxyAccount>,
) -> Result<Json<Value>, AppError> {
    let existing = state
        .db
        .get_proxy_account_by_id(&id)?
        .ok_or_else(|| AppError::NotFound("Proxy account not found".into()))?;
    let label = body.label.as_deref().map(validate_label).transpose()?;
    let update_owner = body.owner_user_id.is_some() || body.clear_owner.unwrap_or(false);
    let owner_user_id = normalize_owner(body.owner_user_id.as_deref());
    if update_owner {
        validate_owner(&state, owner_user_id.as_deref(), Some(&existing.id))?;
    }
    let account = state
        .db
        .update_proxy_account(
            &id,
            label.as_deref(),
            update_owner,
            owner_user_id.as_deref(),
            body.enabled,
        )
        .map_err(map_account_write_error)?
        .ok_or_else(|| AppError::NotFound("Proxy account not found".into()))?;
    state.proxy_accounts.remove(&existing.username);
    state
        .proxy_accounts
        .insert(account.username.clone(), account.clone());
    if !account.enabled {
        crate::proxy_rotation::remove_principal_sessions(&state, &account.id);
    }
    Ok(Json(json!({ "account": account })))
}

pub async fn delete_admin_account(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let existing = state
        .db
        .get_proxy_account_by_id(&id)?
        .ok_or_else(|| AppError::NotFound("Proxy account not found".into()))?;
    if !state.db.delete_proxy_account(&id)? {
        return Err(AppError::NotFound("Proxy account not found".into()));
    }
    state.proxy_accounts.remove(&existing.username);
    state.proxy_account_last_used.remove(&id);
    crate::proxy_rotation::remove_principal_sessions(&state, &id);
    Ok(Json(json!({ "message": "Proxy account deleted" })))
}

pub async fn reveal_admin_credential(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    ensure_credentials_configured(&state)?;
    let account = state
        .db
        .get_proxy_account_by_id(&id)?
        .ok_or_else(|| AppError::NotFound("Proxy account not found".into()))?;
    Ok(no_store_credential_response(&state, &account))
}

pub async fn rotate_admin_credential(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    ensure_credentials_configured(&state)?;
    let account = state
        .db
        .rotate_proxy_account(&id)?
        .ok_or_else(|| AppError::NotFound("Proxy account not found".into()))?;
    state
        .proxy_accounts
        .insert(account.username.clone(), account.clone());
    Ok(no_store_credential_response(&state, &account))
}

fn ensure_credentials_configured(state: &AppState) -> Result<(), AppError> {
    if state.config.proxy_access.credential_secret.as_bytes().len() < 32 {
        return Err(AppError::BadRequest(
            "Proxy account credentials are not configured".into(),
        ));
    }
    Ok(())
}

fn get_or_create_user_account(state: &AppState, user: &User) -> Result<ProxyAccount, AppError> {
    if !state.config.proxy_access.accounts_enabled() {
        return Err(AppError::BadRequest(
            "Independent proxy accounts are not enabled".into(),
        ));
    }
    if let Some(account) = state.db.get_proxy_account_for_owner(&user.id)? {
        return Ok(account);
    }
    ensure_credentials_configured(state)?;

    let now = chrono::Utc::now().to_rfc3339();
    let account = ProxyAccount {
        id: uuid::Uuid::new_v4().to_string(),
        label: automatic_account_label(user),
        username: format!(
            "zp_{}",
            uuid::Uuid::new_v4().simple().to_string().chars().take(12).collect::<String>()
        ),
        owner_user_id: Some(user.id.clone()),
        enabled: true,
        credential_version: 1,
        last_used_at: None,
        created_at: now.clone(),
        updated_at: now,
    };

    match state.db.insert_proxy_account(&account) {
        Ok(()) => {
            state
                .proxy_accounts
                .insert(account.username.clone(), account.clone());
            Ok(account)
        }
        Err(error) if error.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
            // Concurrent first-page requests can race. The owner uniqueness
            // constraint selects the winner; all callers then use that row.
            state
                .db
                .get_proxy_account_for_owner(&user.id)?
                .ok_or_else(|| map_account_write_error(error))
        }
        Err(error) => Err(map_account_write_error(error)),
    }
}

fn automatic_account_label(user: &User) -> String {
    let name = user
        .name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&user.username)
        .trim();
    let shortened: String = name.chars().take(68).collect();
    format!("{shortened} 的代理账号")
}

fn validate_label(label: &str) -> Result<String, AppError> {
    let label = label.trim();
    if label.is_empty() || label.chars().count() > 80 {
        return Err(AppError::BadRequest(
            "Label must contain between 1 and 80 characters".into(),
        ));
    }
    Ok(label.to_string())
}

fn normalize_owner(owner: Option<&str>) -> Option<String> {
    owner
        .map(str::trim)
        .filter(|owner| !owner.is_empty())
        .map(str::to_string)
}

fn validate_owner(
    state: &AppState,
    owner: Option<&str>,
    allowed_account_id: Option<&str>,
) -> Result<(), AppError> {
    if let Some(owner) = owner {
        if state.db.get_user_by_id(owner)?.is_none() {
            return Err(AppError::BadRequest("Assigned user does not exist".into()));
        }
        if let Some(account) = state.db.get_proxy_account_for_owner(owner)? {
            if Some(account.id.as_str()) != allowed_account_id {
                return Err(AppError::BadRequest(
                    "Assigned user already has a proxy account".into(),
                ));
            }
        }
    }
    Ok(())
}

fn map_account_write_error(error: postgres::Error) -> AppError {
    if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
        AppError::BadRequest("Username or assigned user is already in use".into())
    } else if error.code() == Some(&SqlState::FOREIGN_KEY_VIOLATION) {
        AppError::BadRequest("Assigned user does not exist".into())
    } else {
        AppError::Internal(format!("Database error: {error}"))
    }
}

fn no_store_credential_response(state: &AppState, account: &ProxyAccount) -> Response {
    let password = crate::proxy_account::derive_password(
        &state.config.proxy_access.credential_secret,
        &account.id,
        account.credential_version,
    );
    let mut response = Json(json!({
        "account": account,
        "gateway": gateway_json(state),
        "password": password,
    }))
    .into_response();
    response.headers_mut().insert(
        "Cache-Control",
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
}

fn gateway_json(state: &AppState) -> Value {
    json!({
        "host": state.config.proxy_access.public_host,
        "port": state.config.proxy_access.public_port,
        "protocols": ["http", "socks5h"],
    })
}

fn filter_metadata(stats: &Value) -> Value {
    let mut countries: Vec<String> = stats
        .get("by_country")
        .and_then(Value::as_object)
        .map(|items| items.keys().cloned().collect())
        .unwrap_or_default();
    countries.sort();
    let mut proxy_types: Vec<String> = stats
        .get("by_type")
        .and_then(Value::as_object)
        .map(|items| items.keys().cloned().collect())
        .unwrap_or_default();
    proxy_types.sort();
    json!({
        "countries": countries,
        "proxy_types": proxy_types,
        "flags": ["residential", "chatgpt", "google"],
    })
}
