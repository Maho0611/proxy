use crate::db::FixedProxySlot;
use crate::pool::manager::{PoolProxy, ProxyFilter};
use crate::AppState;
use postgres::error::SqlState;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

pub const MAX_SLOTS_PER_ACCOUNT: usize = 500;
const CANDIDATE_SCAN_LIMIT: usize = 1_000;

pub fn valid_country(value: &str) -> bool {
    (2..=8).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

pub fn valid_slot_key(value: &str) -> bool {
    (1..=32).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub fn new_slot_key() -> String {
    format!(
        "f{}",
        uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(16)
            .collect::<String>()
    )
}

pub fn slot_filter(slot: &FixedProxySlot) -> ProxyFilter {
    ProxyFilter {
        country: Some(slot.country.clone()),
        proxy_type: slot.proxy_type.clone(),
        residential: slot.residential,
        chatgpt: slot.chatgpt,
        google: slot.google,
        ..ProxyFilter::default()
    }
}

pub fn candidate_exit_ip(proxy: &PoolProxy) -> Option<String> {
    proxy
        .quality
        .as_ref()
        .and_then(|quality| quality.ip_address.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Resolve a slot only when the persisted assignment still represents the
/// same valid, current-region exit. A changed measured IP is reconciled before
/// it can be used so two slots cannot silently converge on one exit.
pub fn current_slot_proxy(state: &AppState, slot: &FixedProxySlot) -> Result<PoolProxy, String> {
    let Some((row, quality)) = state
        .db
        .get_proxy_record(&slot.proxy_id)
        .map_err(|error| format!("database lookup failed: {error}"))?
    else {
        return Err("proxy_missing".into());
    };
    if !row.is_valid {
        return Err("proxy_invalid".into());
    }
    if row.orphaned_at.is_some() {
        return Err("proxy_removed_by_subscription".into());
    }
    if slot
        .proxy_type
        .as_deref()
        .map(|expected| row.proxy_type != expected)
        .unwrap_or(false)
    {
        return Err("proxy_type_changed".into());
    }
    let quality = quality.ok_or_else(|| "quality_missing".to_string())?;
    let exit_ip = quality
        .ip_address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "exit_ip_missing".to_string())?;
    let country = quality
        .country
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "country_missing".to_string())?;
    if !country.eq_ignore_ascii_case(&slot.country) {
        return Err("country_changed".into());
    }
    if exit_ip != slot.exit_ip {
        return Err("exit_ip_changed".into());
    }
    if slot.residential && !quality.is_residential
        || slot.chatgpt && !quality.chatgpt_accessible
        || slot.google && !quality.google_accessible
    {
        return Err("quality_filter_changed".into());
    }

    Ok(crate::pool::manager::ProxyPool::from_db_parts(
        row,
        Some(quality),
    ))
}

pub fn allocation_candidates(
    state: &AppState,
    account_id: &str,
    filter: &ProxyFilter,
) -> Result<Vec<PoolProxy>, String> {
    let used_ips: HashSet<String> = state
        .db
        .get_fixed_proxy_slots(account_id)
        .map_err(|error| format!("failed to load fixed exits: {error}"))?
        .into_iter()
        .map(|slot| slot.exit_ip)
        .collect();
    let candidates =
        crate::api::fetch::pick_random_valid_proxies(state, filter, CANDIDATE_SCAN_LIMIT)
            .map_err(|error| error.to_string())?;
    Ok(candidates
        .into_iter()
        .filter(|proxy| {
            candidate_exit_ip(proxy)
                .map(|exit_ip| !used_ips.contains(&exit_ip))
                .unwrap_or(false)
        })
        .collect())
}

pub fn replacement_candidates(
    state: &AppState,
    slot: &FixedProxySlot,
    force_different: bool,
) -> Result<Vec<PoolProxy>, String> {
    let used_ips: HashSet<String> = state
        .db
        .get_fixed_proxy_slots(&slot.account_id)
        .map_err(|error| format!("failed to load fixed exits: {error}"))?
        .into_iter()
        .filter(|other| other.id != slot.id)
        .map(|other| other.exit_ip)
        .collect();
    let candidates = crate::api::fetch::pick_random_valid_proxies(
        state,
        &slot_filter(slot),
        CANDIDATE_SCAN_LIMIT,
    )
    .map_err(|error| error.to_string())?;
    Ok(candidates
        .into_iter()
        .filter(|proxy| {
            let Some(exit_ip) = candidate_exit_ip(proxy) else {
                return false;
            };
            if used_ips.contains(&exit_ip) {
                return false;
            }
            if force_different && (proxy.id == slot.proxy_id || exit_ip == slot.exit_ip) {
                return false;
            }
            true
        })
        .collect())
}

pub fn slot_lock(state: &AppState, slot_id: &str) -> Arc<Mutex<()>> {
    state
        .fixed_proxy_slot_locks
        .entry(slot_id.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

pub fn update_assignment(
    state: &AppState,
    slot: &FixedProxySlot,
    proxy: &PoolProxy,
    reason: &str,
) -> Result<FixedProxySlot, String> {
    let exit_ip = candidate_exit_ip(proxy).ok_or_else(|| "candidate has no exit IP".to_string())?;
    state
        .db
        .update_fixed_proxy_slot_assignment(&slot.account_id, &slot.id, &proxy.id, &exit_ip, reason)
        .map_err(|error| {
            if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
                "candidate exit is already assigned to another slot".to_string()
            } else {
                format!("failed to update fixed exit: {error}")
            }
        })?
        .ok_or_else(|| "fixed exit slot no longer exists".to_string())
}

async fn replace_slot(
    state: &Arc<AppState>,
    account_id: &str,
    slot_id: &str,
    force_different: bool,
    reason: &str,
) -> Result<FixedProxySlot, String> {
    let lock = slot_lock(state, slot_id);
    let _guard = lock.lock().await;
    let slot = state
        .db
        .get_fixed_proxy_slot_by_id(account_id, slot_id)
        .map_err(|error| format!("failed to load fixed exit: {error}"))?
        .ok_or_else(|| "fixed exit slot not found".to_string())?;

    if !force_different && current_slot_proxy(state, &slot).is_ok() {
        return Ok(slot);
    }

    let candidates = replacement_candidates(state, &slot, force_different)?;
    for candidate in candidates {
        match update_assignment(state, &slot, &candidate, reason) {
            Ok(updated) => {
                tracing::info!(
                    slot_id = updated.id,
                    account_id = updated.account_id,
                    country = updated.country,
                    exit_ip = updated.exit_ip,
                    reason,
                    "Fixed exit slot replaced"
                );
                return Ok(updated);
            }
            Err(error) if error.contains("already assigned") => continue,
            Err(error) => return Err(error),
        }
    }
    Err(format!(
        "no replacement exit is currently available in {}",
        slot.country
    ))
}

pub async fn force_replace_slot(
    state: &Arc<AppState>,
    account_id: &str,
    slot_id: &str,
    reason: &str,
) -> Result<FixedProxySlot, String> {
    replace_slot(state, account_id, slot_id, true, reason).await
}

pub async fn reconcile_slot(
    state: &Arc<AppState>,
    account_id: &str,
    slot_id: &str,
) -> Result<FixedProxySlot, String> {
    let slot = state
        .db
        .get_fixed_proxy_slot_by_id(account_id, slot_id)
        .map_err(|error| format!("failed to load fixed exit: {error}"))?
        .ok_or_else(|| "fixed exit slot not found".to_string())?;
    let reason = match current_slot_proxy(state, &slot) {
        Ok(_) => return Ok(slot),
        Err(reason) => reason,
    };
    replace_slot(state, account_id, slot_id, false, &reason).await
}

pub async fn reconcile_account(state: &Arc<AppState>, account_id: &str) -> usize {
    match state.db.get_proxy_account_by_id(account_id) {
        Ok(Some(account)) if account.enabled => {}
        Ok(_) => return 0,
        Err(error) => {
            tracing::warn!(account_id, "Failed to load fixed-exit account: {error}");
            return 0;
        }
    }
    let slots = match state.db.get_fixed_proxy_slots(account_id) {
        Ok(slots) => slots,
        Err(error) => {
            tracing::warn!(
                account_id,
                "Failed to load fixed exits for reconciliation: {error}"
            );
            return 0;
        }
    };
    let mut replaced = 0;
    for slot in slots {
        if current_slot_proxy(state, &slot).is_ok() {
            continue;
        }
        match reconcile_slot(state, account_id, &slot.id).await {
            Ok(updated) if updated.proxy_id != slot.proxy_id || updated.exit_ip != slot.exit_ip => {
                replaced += 1;
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(
                slot_id = slot.id,
                country = slot.country,
                "Fixed exit reconciliation deferred: {error}"
            ),
        }
    }
    replaced
}

pub async fn reconcile_all(state: &Arc<AppState>) -> usize {
    let slots = match state.db.get_all_fixed_proxy_slots() {
        Ok(slots) => slots,
        Err(error) => {
            tracing::warn!("Failed to load fixed exits for reconciliation: {error}");
            return 0;
        }
    };
    let account_ids: HashSet<String> = slots.into_iter().map(|slot| slot.account_id).collect();
    let mut replaced = 0;
    for account_id in account_ids {
        replaced += reconcile_account(state, &account_id).await;
    }
    replaced
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_and_slot_keys_are_restricted_to_username_safe_values() {
        assert!(valid_country("US"));
        assert!(valid_country("GBR"));
        assert!(!valid_country("U-S"));
        assert!(!valid_country(""));
        assert!(valid_slot_key("f123_abc"));
        assert!(!valid_slot_key("bad-key"));
    }

    #[test]
    fn generated_slot_keys_are_safe_and_compact() {
        let key = new_slot_key();
        assert!(valid_slot_key(&key));
        assert_eq!(key.len(), 17);
    }
}
