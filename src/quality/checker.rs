use crate::db::ProxyQuality;
use crate::pool::manager::{PoolProxy, ProxyQualityInfo};
use crate::AppState;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;

/// Incomplete quality data can be retried at most this many times.
pub(crate) const MAX_INCOMPLETE_RETRIES: u8 = 2;
pub(crate) const QUALITY_SCHEMA_VERSION: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QualityProfile {
    Basic,
    Full,
}

/// ip-api.com rate limiter: max 40 requests/minute (free tier limit is 45).
struct RateLimiter {
    next_slot: Mutex<Instant>,
    min_interval: std::time::Duration,
    wait_calls: AtomicU64,
    wait_total_micros: AtomicU64,
}

struct RunningGuard<'a> {
    flag: &'a AtomicBool,
}

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

fn acquire_running_guard(flag: &AtomicBool) -> Option<RunningGuard<'_>> {
    flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| RunningGuard { flag })
}

impl RateLimiter {
    fn new(calls_per_minute: u32) -> Self {
        RateLimiter {
            next_slot: Mutex::new(Instant::now()),
            min_interval: std::time::Duration::from_millis(60_000 / calls_per_minute as u64),
            wait_calls: AtomicU64::new(0),
            wait_total_micros: AtomicU64::new(0),
        }
    }

    async fn wait(&self) {
        let sleep_until = {
            let mut next_slot = self.next_slot.lock().await;
            let now = Instant::now();
            let reserved = (*next_slot).max(now);
            *next_slot = reserved + self.min_interval;
            reserved
        };
        let wait_started = Instant::now();
        tokio::time::sleep_until(sleep_until).await;
        let waited = wait_started.elapsed();
        self.wait_calls.fetch_add(1, Ordering::Relaxed);
        self.wait_total_micros.fetch_add(
            waited.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
    }

    fn wait_metrics(&self) -> (u64, f64) {
        (
            self.wait_calls.load(Ordering::Relaxed),
            self.wait_total_micros.load(Ordering::Relaxed) as f64 / 1000.0,
        )
    }
}

pub fn start_quality_check(state: Arc<AppState>) -> bool {
    if state
        .quality_running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    state
        .quality_progress
        .begin(None, None, None, "waiting-for-bindings");
    tokio::spawn(async move {
        let _running = RunningGuard {
            flag: &state.quality_running,
        };
        if let Err(error) = run_quality_check(state.clone(), QualityProfile::Full).await {
            state.quality_progress.fail(&error);
            tracing::error!("Manual quality check failed: {error}");
        }
    });
    true
}

/// Returns the number of proxies actually checked.
pub async fn check_all(state: Arc<AppState>) -> Result<usize, String> {
    let _running = match acquire_running_guard(&state.quality_running) {
        Some(guard) => guard,
        None => {
            tracing::info!("Quality check already running, skipping duplicate trigger");
            return Ok(0);
        }
    };

    run_quality_check(state.clone(), QualityProfile::Basic).await
}

async fn run_quality_check(
    state: Arc<AppState>,
    profile: QualityProfile,
) -> Result<usize, String> {
    let run_started = std::time::Instant::now();
    let db_calls_before = state.db.runtime_metrics().calls;
    state
        .quality_progress
        .begin(None, None, None, "waiting-for-bindings");

    let now = chrono::Utc::now();
    let mut total_checked = 0usize;
    let rate_limiter = Arc::new(RateLimiter::new(40));
    let stale_hours = state.config.quality.stale_hours.max(1);
    let max_checks = state.config.quality.max_checks_per_run.max(1);
    let lease_owner = format!("quality-{}", uuid::Uuid::new_v4());
    let lease_seconds = quality_lease_seconds(max_checks, state.config.quality.concurrency);

    // Keep maintenance binding assignments stable until all checks finish.
    let _lock = state.validation_lock.lock().await;
    let to_check = {
        state.quality_progress.set_phase("preparing");
        let stale_before = (now - chrono::Duration::hours(stale_hours as i64)).to_rfc3339();
        let due = match state.db.claim_due_quality_proxy_records(
            max_checks,
            &stale_before,
            MAX_INCOMPLETE_RETRIES,
            QUALITY_SCHEMA_VERSION,
            &lease_owner,
            lease_seconds,
        ) {
            Ok(due) => due,
            Err(error) => {
                let message = format!("读取质检候选失败: {error}");
                state.quality_progress.fail(&message);
                return Err(message);
            }
        };

        if due.is_empty() {
            state.quality_progress.set_total(0);
            state
                .quality_progress
                .finish("没有待质检或已过期的有效代理");
            if let Err(error) = state
                .db
                .set_maintenance_completed_at(crate::db::SETTING_QUALITY_LAST_COMPLETED_AT)
            {
                tracing::warn!("Failed to persist quality completion timestamp: {error}");
            }
            return Ok(0);
        }

        state.quality_progress.set_phase("binding");
        let due_ids: Vec<_> = due.into_iter().map(|(proxy, _)| proxy.id).collect();
        let sync_result = crate::api::subscription::sync_proxy_bindings(
            &state,
            crate::api::subscription::SyncMode::Targeted(due_ids),
        )
        .await;

        sync_result
            .work_ids
            .iter()
            .filter_map(|id| state.pool.get(id))
            .filter(|p| p.status == crate::pool::manager::ProxyStatus::Valid)
            .filter(|p| p.local_port.is_some())
            .filter(|p| needs_quality_check(p, &now, stale_hours))
            .take(max_checks)
            .collect::<Vec<PoolProxy>>()
    };
    state.quality_progress.set_total(to_check.len());

    if !to_check.is_empty() {
        tracing::info!(
            "Quality check: checking {} proxies this run (limit={max_checks}, stale_after={}h)",
            to_check.len(),
            stale_hours,
        );
        state.quality_progress.set_round(1);
        state.quality_progress.set_phase("checking-unlock");
        total_checked += check_batch(&to_check, &state, &rate_limiter, profile).await;
    } else {
        tracing::info!(
            "Quality check: due proxies exist but none received active bindings this round"
        );
    }

    let _ = crate::api::subscription::sync_proxy_bindings(
        &state,
        crate::api::subscription::SyncMode::Normal,
    )
    .await;
    if let Err(error) = state.db.release_quality_leases(&lease_owner) {
        tracing::warn!("Failed to release quality leases for {lease_owner}: {error}");
    }

    if total_checked > 0 {
        if let Err(error) = crate::selection::rebuild(state.as_ref()) {
            tracing::warn!("Failed to rebuild selection snapshot after quality checks: {error}");
        }
        crate::api::fetch::invalidate_stats_cache(state.as_ref());
        crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
        let reconciled = crate::fixed_proxy::reconcile_all(&state).await;
        if reconciled > 0 {
            tracing::info!("Reconciled {reconciled} fixed exits after quality checks");
        }
        let (rate_wait_calls, rate_wait_total_ms) = rate_limiter.wait_metrics();
        let db_calls = state
            .db
            .runtime_metrics()
            .calls
            .saturating_sub(db_calls_before);
        tracing::info!(
            elapsed_ms = run_started.elapsed().as_secs_f64() * 1000.0,
            db_calls,
            rate_wait_calls,
            rate_wait_total_ms,
            "Quality check complete: {total_checked} proxies checked in this run"
        );
    }

    let progress = state.quality_progress.snapshot();
    state.quality_progress.finish(format!(
        "质检完成：检查 {total_checked} 条线路，成功 {}，失败 {}（解锁检测已包含）",
        progress.succeeded, progress.failed
    ));
    if let Err(error) = state
        .db
        .set_maintenance_completed_at(crate::db::SETTING_QUALITY_LAST_COMPLETED_AT)
    {
        tracing::warn!("Failed to persist quality completion timestamp: {error}");
    }

    Ok(total_checked)
}

/// Force IP intelligence and unlock checks for the valid proxy definitions in
/// one subscription, even when their existing quality result is still fresh.
pub fn start_subscription_quality_check(
    state: Arc<AppState>,
    subscription_id: String,
    subscription_name: String,
) -> bool {
    if state
        .quality_running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    state.quality_progress.begin(
        Some(&subscription_id),
        Some(&subscription_name),
        None,
        "waiting-for-bindings",
    );
    tokio::spawn(async move {
        let _running = RunningGuard {
            flag: &state.quality_running,
        };
        if let Err(error) =
            run_subscription_quality_check(state.clone(), subscription_id, subscription_name).await
        {
            state.quality_progress.fail(&error);
            tracing::error!("Manual subscription quality check failed: {error}");
        }
    });
    true
}

async fn run_subscription_quality_check(
    state: Arc<AppState>,
    subscription_id: String,
    subscription_name: String,
) -> Result<usize, String> {
    state.quality_progress.begin(
        Some(&subscription_id),
        Some(&subscription_name),
        None,
        "waiting-for-bindings",
    );
    let _lock = state.validation_lock.lock().await;
    state.quality_progress.set_phase("preparing");
    let rows = match state.db.get_proxies_by_subscription(&subscription_id) {
        Ok(rows) => rows,
        Err(error) => {
            let message = format!("读取订阅代理失败: {error}");
            state.quality_progress.fail(&message);
            return Err(message);
        }
    };
    let mut seen_definitions = std::collections::HashSet::new();
    let target_ids: Vec<String> = rows
        .into_iter()
        .filter(|proxy| proxy.orphaned_at.is_none() && proxy.is_valid)
        .filter(|proxy| {
            seen_definitions.insert(crate::api::subscription::proxy_row_definition_key(proxy))
        })
        .map(|proxy| proxy.id)
        .collect();
    state.quality_progress.set_total(target_ids.len());
    if target_ids.is_empty() {
        state
            .quality_progress
            .finish("该订阅没有已通过验活、可执行解锁质检的代理");
        return Ok(0);
    }

    let rate_limiter = Arc::new(RateLimiter::new(40));
    let batch_size = state.config.validation.batch_size.max(1);
    let mut total_checked = 0usize;
    for (index, target_batch) in target_ids.chunks(batch_size).enumerate() {
        state.quality_progress.set_round(index + 1);
        state.quality_progress.set_phase("binding");
        let sync_result = crate::api::subscription::sync_proxy_bindings(
            &state,
            crate::api::subscription::SyncMode::Targeted(target_batch.to_vec()),
        )
        .await;
        let to_check = sync_result
            .work_ids
            .iter()
            .filter_map(|id| state.pool.get(id))
            .filter(|proxy| proxy.status == crate::pool::manager::ProxyStatus::Valid)
            .filter(|proxy| proxy.local_port.is_some())
            .collect::<Vec<PoolProxy>>();
        for _ in 0..target_batch.len().saturating_sub(to_check.len()) {
            state.quality_progress.advance(false);
        }
        state.quality_progress.set_phase("checking-unlock");
        total_checked +=
            check_batch(&to_check, &state, &rate_limiter, QualityProfile::Full).await;
    }

    let _ = crate::api::subscription::sync_proxy_bindings(
        &state,
        crate::api::subscription::SyncMode::Normal,
    )
    .await;

    if total_checked > 0 {
        if let Err(error) = crate::selection::rebuild(state.as_ref()) {
            tracing::warn!(
                "Failed to rebuild selection snapshot after subscription quality checks: {error}"
            );
        }
        crate::api::fetch::invalidate_stats_cache(state.as_ref());
        crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
        let reconciled = crate::fixed_proxy::reconcile_all(&state).await;
        if reconciled > 0 {
            tracing::info!("Reconciled {reconciled} fixed exits after subscription quality checks");
        }
    }
    let progress = state.quality_progress.snapshot();
    state.quality_progress.finish(format!(
        "订阅“{subscription_name}”解锁质检完成：检查 {total_checked} 条线路，成功 {}，失败 {}",
        progress.succeeded, progress.failed
    ));
    Ok(total_checked)
}

/// Check a batch of proxies concurrently, respecting rate limits.
enum CompletedQualityCheck {
    Success {
        source_id: String,
        quality: ProxyQualityInfo,
        db_quality: Box<ProxyQuality>,
    },
    Failure,
}

async fn check_batch(
    proxies: &[PoolProxy],
    state: &Arc<AppState>,
    rate_limiter: &Arc<RateLimiter>,
    profile: QualityProfile,
) -> usize {
    let semaphore = Arc::new(Semaphore::new(state.config.quality.concurrency.max(1)));
    let mut handles = JoinSet::new();

    for proxy in proxies.iter().cloned() {
        let network = semaphore.clone();
        let rl = rate_limiter.clone();

        handles.spawn(async move {
            let local_port = match proxy.local_port {
                Some(p) => p,
                None => return CompletedQualityCheck::Failure,
            };

            let proxy_addr = format!("http://127.0.0.1:{local_port}");
            match check_single(&proxy_addr, &proxy, &rl, &network, profile).await {
                Ok(result) => {
                    let mut quality = result.quality;
                    // Make the just-collected unlock details visible to the
                    // completeness check. Previously details were attached
                    // only after this check, so provider errors looked like a
                    // complete result and were not retried until the global
                    // stale TTL elapsed.
                    quality.details = Some(result.extra_json.clone());
                    let is_incomplete = quality_is_incomplete(&quality);
                    let incomplete_retry_count = if is_incomplete {
                        proxy
                            .quality
                            .as_ref()
                            .map(|q| q.incomplete_retry_count)
                            .unwrap_or(0)
                            .saturating_add(1)
                    } else {
                        0
                    };

                    tracing::info!(
                        "Quality OK: {} | IP={} country={} type={} residential={} google={}({}) chatgpt={}({}) risk={}({})",
                        proxy.name,
                        quality.ip_address.as_deref().unwrap_or("-"),
                        quality.country.as_deref().unwrap_or("-"),
                        quality.ip_type.as_deref().unwrap_or("-"),
                        quality.is_residential,
                        quality.google_accessible,
                        result.google_detail,
                        quality.chatgpt_accessible,
                        result.chatgpt_detail,
                        quality.risk_score,
                        &quality.risk_level,
                    );
                    let mut extra = result.extra_json;
                    let checked_at = chrono::Utc::now();
                    if let Some(obj) = extra.as_object_mut() {
                        obj.insert(
                            "incomplete_retry_count".to_string(),
                            serde_json::json!(incomplete_retry_count),
                        );
                        if is_incomplete && incomplete_retry_count < MAX_INCOMPLETE_RETRIES {
                            obj.insert(
                                "next_retry_at".to_string(),
                                serde_json::json!(
                                    (checked_at
                                        + incomplete_retry_delay(incomplete_retry_count))
                                    .to_rfc3339()
                                ),
                            );
                        }
                    }
                    quality.checked_at = Some(checked_at.to_rfc3339());
                    quality.details = Some(extra.clone());
                    let db_quality = ProxyQuality {
                        proxy_id: proxy.id.clone(),
                        ip_address: quality.ip_address.clone(),
                        country: quality.country.clone(),
                        ip_type: quality.ip_type.clone(),
                        is_residential: quality.is_residential,
                        chatgpt_accessible: quality.chatgpt_accessible,
                        google_accessible: quality.google_accessible,
                        risk_score: quality.risk_score,
                        risk_level: quality.risk_level.clone(),
                        extra_json: Some(extra.to_string()),
                        checked_at: checked_at.to_rfc3339(),
                    };
                    quality.incomplete_retry_count = incomplete_retry_count;
                    CompletedQualityCheck::Success {
                        source_id: proxy.id,
                        quality,
                        db_quality: Box::new(db_quality),
                    }
                }
                Err(e) => {
                    tracing::warn!("Quality check failed for {}: {e}", proxy.name);
                    CompletedQualityCheck::Failure
                }
            }
        });
    }

    let mut successful_checks = Vec::new();
    while let Some(result) = handles.join_next().await {
        match result {
            Ok(CompletedQualityCheck::Success {
                source_id,
                quality,
                db_quality,
            }) => successful_checks.push((source_id, quality, *db_quality)),
            Ok(CompletedQualityCheck::Failure) => state.quality_progress.advance(false),
            Err(error) => {
                tracing::warn!("Quality check task failed to join: {error}");
                state.quality_progress.advance(false);
            }
        }
    }

    if successful_checks.is_empty() {
        return 0;
    }
    let db_qualities: Vec<_> = successful_checks
        .iter()
        .map(|(_, _, quality)| quality.clone())
        .collect();
    let critical_unlock_errors = db_qualities
        .iter()
        .filter_map(|quality| quality.extra_json.as_deref())
        .filter_map(|json| serde_json::from_str::<serde_json::Value>(json).ok())
        .map(|details| {
            ["google", "chatgpt"]
                .into_iter()
                .filter(|service| {
                    details["unlock"][*service]["status"].as_str() == Some("error")
                })
                .count()
        })
        .sum::<usize>();
    tracing::info!(
        critical_unlock_errors,
        critical_unlock_checks = db_qualities.len().saturating_mul(2),
        "Quality batch critical unlock transport-error ratio"
    );
    let applied = match state.db.apply_quality_outcomes(&db_qualities) {
        Ok(applied) => applied,
        Err(error) => {
            tracing::warn!(
                "Failed to persist quality batch of {} checks: {error}",
                successful_checks.len()
            );
            for _ in &successful_checks {
                state.quality_progress.advance(false);
            }
            return 0;
        }
    };

    let quality_by_source: std::collections::HashMap<_, _> = successful_checks
        .iter()
        .map(|(source_id, quality, _)| (source_id.as_str(), quality))
        .collect();
    let applied_sources: std::collections::HashSet<_> = applied
        .iter()
        .map(|result| result.source_id.clone())
        .collect();
    for result in applied {
        if let Some(quality) = quality_by_source.get(result.source_id.as_str()) {
            state.pool.set_quality(&result.proxy_id, (*quality).clone());
        }
    }

    let mut count = 0;
    for (source_id, _, _) in &successful_checks {
        let succeeded = applied_sources.contains(source_id.as_str());
        if succeeded {
            count += 1;
        }
        state.quality_progress.advance(succeeded);
    }
    count
}

/// Check if a proxy needs a quality check: no quality data, incomplete data, or stale.
pub(crate) fn needs_quality_check(
    proxy: &PoolProxy,
    now: &chrono::DateTime<chrono::Utc>,
    stale_hours: u64,
) -> bool {
    match &proxy.quality {
        None => true,
        Some(q) => {
            // An expired record is due even after its short-term incomplete retry
            // budget was exhausted. Otherwise an incomplete record could remain
            // excluded forever.
            if quality_checked_at_is_stale(q.checked_at.as_deref(), now, stale_hours) {
                return true;
            }

            // Re-run otherwise-fresh legacy records once when the stored
            // detail schema does not yet contain IPPure and unlock metadata.
            if q.details
                .as_ref()
                .and_then(|details| details.get("schema_version"))
                .and_then(serde_json::Value::as_u64)
                != Some(QUALITY_SCHEMA_VERSION as u64)
            {
                return true;
            }

            // Fresh incomplete data uses a bounded, persisted backoff. This
            // includes critical unlock provider errors, which are unknown but
            // must not monopolize every quality run during a provider outage.
            if quality_is_incomplete(q) {
                return q.incomplete_retry_count < MAX_INCOMPLETE_RETRIES
                    && incomplete_retry_is_due(q.details.as_ref(), now);
            }

            false
        }
    }
}

fn incomplete_retry_delay(retry_count: u8) -> chrono::Duration {
    let exponent = retry_count.saturating_sub(1).min(4) as u32;
    chrono::Duration::minutes(5_i64.saturating_mul(4_i64.pow(exponent)))
}

fn quality_lease_seconds(max_checks: usize, concurrency: usize) -> u64 {
    let max_checks = max_checks.max(1) as u64;
    let concurrency = concurrency.max(1) as u64;
    let waves = max_checks / concurrency + u64::from(max_checks % concurrency != 0);
    // A workflow can perform a primary metadata request, fallback metadata,
    // and an unlock profile. The separate rate-limit budget covers the
    // serialized ip-api queue without holding a network permit.
    waves
        .saturating_mul(120)
        .saturating_add(max_checks.saturating_mul(2))
        .saturating_add(120)
        .max(15 * 60)
}

fn incomplete_retry_is_due(
    details: Option<&serde_json::Value>,
    now: &chrono::DateTime<chrono::Utc>,
) -> bool {
    let Some(next_retry_at) = details
        .and_then(|details| details.get("next_retry_at"))
        .and_then(serde_json::Value::as_str)
    else {
        return true;
    };
    chrono::DateTime::parse_from_rfc3339(next_retry_at)
        .map(|next| next.with_timezone(&chrono::Utc) <= *now)
        .unwrap_or(true)
}

pub(crate) fn quality_checked_at_is_stale(
    checked_at: Option<&str>,
    now: &chrono::DateTime<chrono::Utc>,
    stale_hours: u64,
) -> bool {
    let Some(checked_at) = checked_at else {
        return true;
    };
    match chrono::DateTime::parse_from_rfc3339(checked_at) {
        Ok(checked_at) => {
            *now - checked_at.with_timezone(&chrono::Utc)
                >= chrono::Duration::hours(stale_hours.max(1) as i64)
        }
        Err(_) => true,
    }
}

fn quality_is_incomplete(q: &ProxyQualityInfo) -> bool {
    q.country.is_none()
        || q.ip_type.is_none()
        || q.ip_address.is_none()
        || q.risk_level == "Unknown"
        || critical_unlock_check_failed(q.details.as_ref())
}

fn critical_unlock_check_failed(details: Option<&serde_json::Value>) -> bool {
    let Some(unlock) = details.and_then(|details| details.get("unlock")) else {
        return false;
    };
    ["google", "chatgpt"].iter().any(|service| {
        unlock
            .get(service)
            .and_then(|result| result.get("status"))
            .and_then(serde_json::Value::as_str)
            == Some("error")
    })
}

fn merge_unlock_availability(current: Option<bool>, previous: Option<bool>) -> bool {
    current.or(previous).unwrap_or(false)
}

/// IP info from ip-api.com (primary source — free, no key, auto-detects caller IP)
struct IpApiResult {
    ip: Option<String>,
    country: Option<String>,
    is_proxy: bool,
    is_hosting: bool,
}

#[derive(Debug, Default)]
struct IpPureResult {
    ip: Option<String>,
    asn: Option<u64>,
    as_organization: Option<String>,
    country_name: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    region_code: Option<String>,
    city: Option<String>,
    timezone: Option<String>,
    longitude: Option<String>,
    latitude: Option<String>,
    postal_code: Option<String>,
    fraud_score: Option<f64>,
    is_residential: Option<bool>,
    is_broadcast: Option<bool>,
    is_datacenter: Option<bool>,
    is_native: Option<bool>,
}

#[derive(Debug, PartialEq, Eq)]
struct ProviderIpSelection<'a> {
    selected: Option<&'a str>,
    ippure_matches: bool,
    ipinfo_matches: bool,
    ip_api_matches: bool,
    mismatch: bool,
}

fn select_provider_ip<'a>(
    ippure: Option<&'a str>,
    ipinfo: Option<&'a str>,
    ip_api: Option<&'a str>,
    validation: Option<&'a str>,
) -> ProviderIpSelection<'a> {
    let selected = ippure.or(ipinfo).or(ip_api).or(validation);
    let observed: std::collections::HashSet<_> =
        [ippure, ipinfo, ip_api, validation].into_iter().flatten().collect();
    ProviderIpSelection {
        selected,
        ippure_matches: ippure.is_some() && ippure == selected,
        ipinfo_matches: ipinfo.is_some() && ipinfo == selected,
        ip_api_matches: ip_api.is_some() && ip_api == selected,
        mismatch: observed.len() > 1,
    }
}

struct QualityCheckResult {
    quality: ProxyQualityInfo,
    extra_json: serde_json::Value,
    google_detail: String,
    chatgpt_detail: String,
}

async fn check_single(
    proxy_addr: &str,
    proxy: &PoolProxy,
    rate_limiter: &RateLimiter,
    network_semaphore: &Semaphore,
    profile: QualityProfile,
) -> Result<QualityCheckResult, String> {
    let reqwest_proxy = reqwest::Proxy::all(proxy_addr).map_err(|e| e.to_string())?;
    // no_proxy() must come BEFORE .proxy() — it clears all proxies and disables
    // env var detection; the subsequent .proxy() then adds our explicit proxy back.
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest_proxy)
        .user_agent(crate::quality::unlock::BROWSER_USER_AGENT)
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| e.to_string())?;

    // Unlock checks do not depend on IP metadata. Run them from the beginning
    // while the metadata branch first tries IPPure and only then schedules
    // fallback providers. IP-api rate waiting is outside the shared network
    // semaphore so a five-minute provider queue cannot consume every proxy
    // workflow slot.
    let ((ippure_result, ipapi_result, ipinfo_result), mut unlock_report) = tokio::join!(
        async {
            let ippure_result =
                with_network_permit(network_semaphore, query_ippure(&client)).await;
            let need_ip_api = ippure_result
                .as_ref()
                .map(|result| {
                    result.ip.is_none()
                        || result.country_code.is_none()
                        || result.fraud_score.is_none()
                })
                .unwrap_or(true);
            let need_ipinfo = ippure_result
                .as_ref()
                .map(|result| {
                    result.ip.is_none()
                        || result.country_code.is_none()
                        || (result.is_residential.is_none()
                            && result.is_datacenter.is_none())
                })
                .unwrap_or(true);
            let (ipapi_result, ipinfo_result) = tokio::join!(
                async {
                    if need_ip_api {
                        query_ip_api(&client, rate_limiter).await
                    } else {
                        None
                    }
                },
                async {
                    if need_ipinfo {
                        with_network_permit(network_semaphore, query_ipinfo(&client)).await
                    } else {
                        None
                    }
                },
            );
            (ippure_result, ipapi_result, ipinfo_result)
        },
        with_network_permit(
            network_semaphore,
            async {
                match profile {
                    QualityProfile::Basic => crate::quality::unlock::check_basic(&client).await,
                    QualityProfile::Full => crate::quality::unlock::check_all(&client).await,
                }
            },
        ),
    );

    if profile == QualityProfile::Basic {
        let mut merged = proxy
            .quality
            .as_ref()
            .and_then(|quality| quality.details.as_ref())
            .and_then(|details| details.get("unlock"))
            .and_then(serde_json::Value::as_object)
            .cloned()
            .unwrap_or_default();
        if let Some(current) = unlock_report.checks.as_object() {
            for (service, result) in current {
                merged.insert(service.clone(), result.clone());
            }
        }
        unlock_report.checks = serde_json::Value::Object(merged);
    }

    let ippure_ok = ippure_result.is_some();
    let ip_api_ok = ipapi_result.is_some();
    let ipinfo_ok = ipinfo_result.is_some();

    // Pick one observed address first, then accept metadata only from providers
    // that explicitly report that same address. Mixing country/risk/type from
    // different rotating exits produces a record that describes no real IP.
    let validation_ip = proxy
        .quality
        .as_ref()
        .and_then(|quality| quality.ip_address.clone());
    let ippure_ip = ippure_result
        .as_ref()
        .and_then(|result| result.ip.as_deref());
    let ipinfo_ip = ipinfo_result
        .as_ref()
        .and_then(|(ip, _, _, _)| ip.as_deref());
    let ipapi_ip = ipapi_result
        .as_ref()
        .and_then(|result| result.ip.as_deref());
    let provider_selection =
        select_provider_ip(ippure_ip, ipinfo_ip, ipapi_ip, validation_ip.as_deref());
    let ip_address = provider_selection.selected.map(str::to_string);
    let ippure_selected = ippure_result
        .as_ref()
        .filter(|_| provider_selection.ippure_matches);
    let ipinfo_selected = ipinfo_result
        .as_ref()
        .filter(|_| provider_selection.ipinfo_matches);
    let ipapi_selected = ipapi_result
        .as_ref()
        .filter(|_| provider_selection.ip_api_matches);
    let ip_mismatch = provider_selection.mismatch;

    let country = ippure_selected
        .and_then(|result| result.country_code.clone())
        .or_else(|| ipinfo_selected.and_then(|(_, country, _, _)| country.clone()))
        .or_else(|| ipapi_selected.and_then(|result| result.country.clone()));
    let ippure_residential = ippure_selected.and_then(|result| result.is_residential);
    let ippure_datacenter = ippure_selected.and_then(|result| result.is_datacenter);
    let ipinfo_residential = ipinfo_selected
        .map(|(_, _, _, residential)| *residential)
        .unwrap_or(false);
    let mut is_residential = ippure_residential.unwrap_or(ipinfo_residential);
    let mut ip_type = match (ippure_residential, ippure_datacenter) {
        (Some(true), _) => Some("Residential".to_string()),
        (Some(false), _) | (_, Some(true)) => Some("Datacenter".to_string()),
        (_, Some(false)) => Some("Native/ISP".to_string()),
        _ => ipinfo_selected.and_then(|(_, _, ip_type, _)| ip_type.clone()),
    };

    // Prefer IPPure's 0-100 fraud score. ip-api.com's coarse proxy/hosting
    // matrix is retained only when IPPure omits fraudScore.
    let (fallback_risk_score, fallback_risk_level, is_hosting) = match ipapi_selected {
        Some(r) => {
            let (score, level) = match (r.is_proxy, r.is_hosting) {
                (true, true) => (0.9, "Very High"),
                (true, false) => (0.7, "High"),
                (false, true) => (0.5, "Medium"),
                (false, false) => (0.1, "Low"),
            };
            (score, level.to_string(), r.is_hosting)
        }
        None => (0.5, "Unknown".to_string(), false),
    };
    let (risk_score, risk_level) = ippure_selected
        .and_then(|result| result.fraud_score)
        .map(|score| {
            let normalized = (score.clamp(0.0, 100.0)) / 100.0;
            (normalized, risk_level(normalized).to_string())
        })
        .unwrap_or((fallback_risk_score, fallback_risk_level));

    // A primary IPPure classification wins over the fallback hosting flag.
    if ippure_residential.is_none() && ippure_datacenter.is_none() && is_hosting {
        is_residential = false;
        ip_type = Some("Datacenter".to_string());
    }

    let google_detail = unlock_report.google_detail.clone();
    let chatgpt_detail = unlock_report.chatgpt_detail.clone();
    // A transport/provider error is unknown, not unavailable. Preserve the
    // last definitive value until a later check can replace it. New proxies
    // still default to false for compatibility, while their JSON detail keeps
    // the explicit `error` state and makes them immediately due for retry.
    let google_accessible = merge_unlock_availability(
        unlock_report.google_available,
        proxy
            .quality
            .as_ref()
            .map(|quality| quality.google_accessible),
    );
    let chatgpt_accessible = merge_unlock_availability(
        unlock_report.chatgpt_available,
        proxy
            .quality
            .as_ref()
            .map(|quality| quality.chatgpt_accessible),
    );
    let ip_details = ippure_metadata(
        ippure_selected,
        ip_address.as_deref(),
        country.as_deref(),
        is_residential,
        ip_type.as_deref(),
        risk_score,
        &risk_level,
    );
    let google_check = unlock_report.checks.get("google").cloned();
    let chatgpt_check = unlock_report.checks.get("chatgpt").cloned();

    Ok(QualityCheckResult {
        quality: ProxyQualityInfo {
            ip_address: ip_address.clone(),
            country,
            ip_type,
            is_residential,
            chatgpt_accessible,
            google_accessible,
            risk_score,
            risk_level,
            checked_at: Some(chrono::Utc::now().to_rfc3339()),
            details: None,
            incomplete_retry_count: 0,
        },
        extra_json: serde_json::json!({
            "schema_version": QUALITY_SCHEMA_VERSION,
            "ippure_ok": ippure_ok,
            "ip_api_ok": ip_api_ok,
            "ipinfo_ok": ipinfo_ok,
            "ip_consistency": {
                "mismatch": ip_mismatch,
                "selected": ip_address,
                "ippure": ippure_ip,
                "ipinfo": ipinfo_ip,
                "ip_api": ipapi_ip,
                "validation": validation_ip,
            },
            "ip": ip_details,
            "unlock": unlock_report.checks,
            "google_check": google_check,
            "chatgpt_check": chatgpt_check,
        }),
        google_detail,
        chatgpt_detail,
    })
}

async fn with_network_permit<T>(
    semaphore: &Semaphore,
    future: impl Future<Output = T>,
) -> T {
    let _permit = semaphore
        .acquire()
        .await
        .expect("quality network semaphore must remain open");
    future.await
}

/// Query IPPure through the candidate proxy. The public API occasionally
/// omits risk/classification fields, so every field is optional and later
/// merged with the legacy enrichment providers.
async fn query_ippure(client: &reqwest::Client) -> Option<IpPureResult> {
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        let response = match client.get("https://my.ippure.com/v1/info").send().await {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                tracing::warn!(
                    "IPPure returned status {} (attempt {})",
                    response.status(),
                    attempt + 1
                );
                continue;
            }
            Err(error) => {
                tracing::warn!("IPPure request failed (attempt {}): {error}", attempt + 1);
                continue;
            }
        };
        match response.json::<serde_json::Value>().await {
            Ok(body) => match parse_ippure(&body) {
                Some(result) => return Some(result),
                None => tracing::warn!("IPPure response had no usable IP metadata"),
            },
            Err(error) => tracing::warn!(
                "IPPure response parse failed (attempt {}): {error}",
                attempt + 1
            ),
        }
    }
    None
}

fn parse_ippure(body: &serde_json::Value) -> Option<IpPureResult> {
    let result = IpPureResult {
        ip: json_string(body, &["ip"]),
        asn: json_u64(body, &["asn"]),
        as_organization: json_string(body, &["asOrganization", "as_organization", "org"]),
        country_name: json_string(body, &["country"]),
        country_code: json_string(body, &["countryCode", "country_code"])
            .map(|value| value.to_ascii_uppercase()),
        region: json_string(body, &["region"]),
        region_code: json_string(body, &["regionCode", "region_code"]),
        city: json_string(body, &["city"]),
        timezone: json_string(body, &["timezone"]),
        longitude: json_string(body, &["longitude"]),
        latitude: json_string(body, &["latitude"]),
        postal_code: json_string(body, &["postalCode", "postal_code"]),
        fraud_score: json_f64(body, &["fraudScore", "fraud_score"]),
        is_residential: json_bool(body, &["isResidential", "is_residential"]),
        is_broadcast: json_bool(body, &["isBroadcast", "is_broadcast"]),
        is_datacenter: json_bool(
            body,
            &["isDatacenter", "isDataCenter", "is_datacenter", "isHosting"],
        ),
        is_native: json_bool(body, &["isNative", "isNativeIP", "is_native"]),
    };
    if result.ip.is_none()
        && result.asn.is_none()
        && result.country_code.is_none()
        && result.country_name.is_none()
    {
        None
    } else {
        Some(result)
    }
}

fn json_string(body: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        let value = body.get(*key)?;
        let value = match value {
            serde_json::Value::String(value) => value.trim().to_string(),
            serde_json::Value::Number(value) => value.to_string(),
            _ => return None,
        };
        (!value.is_empty()).then_some(value)
    })
}

fn json_u64(body: &serde_json::Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        body.get(*key).and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
    })
}

fn json_f64(body: &serde_json::Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| {
        body.get(*key).and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
    })
}

fn json_bool(body: &serde_json::Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| {
        body.get(*key).and_then(|value| {
            value.as_bool().or_else(|| {
                value
                    .as_str()
                    .and_then(|value| match value.to_ascii_lowercase().as_str() {
                        "true" | "1" | "yes" => Some(true),
                        "false" | "0" | "no" => Some(false),
                        _ => None,
                    })
            })
        })
    })
}

fn risk_level(score: f64) -> &'static str {
    if score <= 0.25 {
        "Low"
    } else if score <= 0.5 {
        "Medium"
    } else if score <= 0.75 {
        "High"
    } else {
        "Very High"
    }
}

#[allow(clippy::too_many_arguments)]
fn ippure_metadata(
    ippure: Option<&IpPureResult>,
    ip_address: Option<&str>,
    country_code: Option<&str>,
    is_residential: bool,
    ip_type: Option<&str>,
    risk_score: f64,
    risk_level: &str,
) -> serde_json::Value {
    let is_broadcast = ippure.and_then(|result| result.is_broadcast);
    let is_native = ippure
        .and_then(|result| result.is_native)
        .or_else(|| is_broadcast.map(|value| !value));
    let is_datacenter = ippure
        .and_then(|result| result.is_datacenter)
        .or_else(|| ippure.and_then(|result| result.is_residential.map(|value| !value)))
        .or_else(|| ip_type.map(|value| value.eq_ignore_ascii_case("datacenter")));
    serde_json::json!({
        "source": if ippure.is_some() { "ippure" } else { "fallback" },
        "ip": ip_address,
        "asn": ippure.and_then(|result| result.asn),
        "as_organization": ippure.and_then(|result| result.as_organization.as_deref()),
        "country": ippure.and_then(|result| result.country_name.as_deref()),
        "country_code": country_code,
        "region": ippure.and_then(|result| result.region.as_deref()),
        "region_code": ippure.and_then(|result| result.region_code.as_deref()),
        "city": ippure.and_then(|result| result.city.as_deref()),
        "timezone": ippure.and_then(|result| result.timezone.as_deref()),
        "longitude": ippure.and_then(|result| result.longitude.as_deref()),
        "latitude": ippure.and_then(|result| result.latitude.as_deref()),
        "postal_code": ippure.and_then(|result| result.postal_code.as_deref()),
        "fraud_score": ippure.and_then(|result| result.fraud_score).unwrap_or(risk_score * 100.0),
        "risk_level": risk_level,
        "is_residential": is_residential,
        "is_datacenter": is_datacenter,
        "is_broadcast": is_broadcast,
        "is_native": is_native,
    })
}

/// Query ip-api.com — auto-detects caller IP, returns IP/country/proxy/hosting.
/// Retries up to 2 times on failure.
async fn query_ip_api(
    client: &reqwest::Client,
    rate_limiter: &RateLimiter,
) -> Option<IpApiResult> {
    let url = "http://ip-api.com/json?fields=query,countryCode,proxy,hosting,status,message";
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        // Every retry is a provider call and must consume its own reserved
        // slot; limiting only the first attempt can exceed the free-tier cap.
        rate_limiter.wait().await;
        let resp = match client.get(url).send().await {
            Ok(r) if r.status().as_u16() == 429 => {
                tracing::warn!(
                    "ip-api.com rate limited (attempt {}), backing off",
                    attempt + 1
                );
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::warn!(
                    "ip-api.com returned status {} (attempt {})",
                    r.status(),
                    attempt + 1
                );
                continue;
            }
            Err(e) => {
                tracing::warn!("ip-api.com request failed (attempt {}): {e}", attempt + 1);
                continue;
            }
        };
        match resp.json::<serde_json::Value>().await {
            Ok(body) if body["status"].as_str() == Some("success") => {
                return Some(IpApiResult {
                    ip: body["query"].as_str().map(|s| s.to_string()),
                    country: body["countryCode"].as_str().map(|s| s.to_string()),
                    is_proxy: body["proxy"].as_bool().unwrap_or(false),
                    is_hosting: body["hosting"].as_bool().unwrap_or(false),
                });
            }
            Ok(body) => {
                tracing::warn!(
                    "ip-api.com returned non-success: {}",
                    body["message"].as_str().unwrap_or("unknown")
                );
                return None; // API-level failure, don't retry
            }
            Err(e) => {
                tracing::warn!("ip-api.com parse failed (attempt {}): {e}", attempt + 1);
            }
        }
    }
    None
}

/// Query ipinfo.io — richer org/company data for residential detection.
/// Retries up to 2 times on failure.
async fn query_ipinfo(
    client: &reqwest::Client,
) -> Option<(Option<String>, Option<String>, Option<String>, bool)> {
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        let resp = match client.get("https://ipinfo.io/json").send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::warn!(
                    "ipinfo.io returned status {} (attempt {})",
                    r.status(),
                    attempt + 1
                );
                continue;
            }
            Err(e) => {
                tracing::warn!("ipinfo.io request failed (attempt {}): {e}", attempt + 1);
                continue;
            }
        };
        match resp.json::<serde_json::Value>().await {
            Ok(body) => {
                let ip = body["ip"].as_str().map(|s| s.to_string());
                let country = body["country"].as_str().map(|s| s.to_string());
                let org = body["org"].as_str().unwrap_or("");
                let org_lower = org.to_lowercase();

                let company_type = body["company"]["type"].as_str().unwrap_or("");

                let (ip_type, is_residential) = if !company_type.is_empty() {
                    let residential = company_type.eq_ignore_ascii_case("isp");
                    (Some(company_type.to_string()), residential)
                } else {
                    let is_datacenter = org_lower.contains("hosting")
                        || org_lower.contains("cloud")
                        || org_lower.contains("server")
                        || org_lower.contains("data center")
                        || org_lower.contains("datacenter")
                        || org_lower.contains("vps")
                        || org_lower.contains("amazon")
                        || org_lower.contains("google")
                        || org_lower.contains("microsoft")
                        || org_lower.contains("digitalocean")
                        || org_lower.contains("linode")
                        || org_lower.contains("vultr")
                        || org_lower.contains("hetzner")
                        || org_lower.contains("ovh")
                        || org_lower.contains("contabo")
                        || org_lower.contains("alibaba")
                        || org_lower.contains("tencent")
                        || org_lower.contains("oracle");

                    if is_datacenter {
                        (Some("Datacenter".to_string()), false)
                    } else {
                        (Some("ISP".to_string()), true)
                    }
                };

                return Some((ip, country, ip_type, is_residential));
            }
            Err(e) => {
                tracing::warn!("ipinfo.io parse failed (attempt {}): {e}", attempt + 1);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_lease_covers_network_and_rate_limit_queues() {
        assert_eq!(quality_lease_seconds(200, 10), 2_920);
        assert_eq!(quality_lease_seconds(1, 100), 900);
    }

    fn proxy_with_quality(checked_at: Option<String>, incomplete_retries: u8) -> PoolProxy {
        PoolProxy {
            id: "proxy-1".into(),
            subscription_id: "sub-1".into(),
            name: "test".into(),
            proxy_type: "vmess".into(),
            server: "example.com".into(),
            port: 443,
            singbox_outbound: serde_json::json!({}),
            status: crate::pool::manager::ProxyStatus::Valid,
            local_port: Some(10001),
            error_count: 0,
            quality: Some(ProxyQualityInfo {
                ip_address: None,
                country: None,
                ip_type: None,
                is_residential: false,
                chatgpt_accessible: false,
                google_accessible: false,
                risk_score: 0.5,
                risk_level: "Unknown".into(),
                checked_at,
                details: Some(serde_json::json!({
                    "schema_version": QUALITY_SCHEMA_VERSION
                })),
                incomplete_retry_count: incomplete_retries,
            }),
        }
    }

    #[test]
    fn fresh_incomplete_quality_stops_after_retry_budget() {
        let now = chrono::Utc::now();
        let proxy = proxy_with_quality(Some(now.to_rfc3339()), MAX_INCOMPLETE_RETRIES);
        assert!(!needs_quality_check(&proxy, &now, 24));
    }

    #[test]
    fn stale_incomplete_quality_is_due_again() {
        let now = chrono::Utc::now();
        let checked_at = (now - chrono::Duration::hours(25)).to_rfc3339();
        let proxy = proxy_with_quality(Some(checked_at), MAX_INCOMPLETE_RETRIES);
        assert!(needs_quality_check(&proxy, &now, 24));
    }

    #[test]
    fn stale_threshold_uses_exact_duration() {
        let now = chrono::Utc::now();
        let fresh = (now - chrono::Duration::minutes(90)).to_rfc3339();
        let stale = (now - chrono::Duration::hours(2)).to_rfc3339();
        assert!(!quality_checked_at_is_stale(Some(&fresh), &now, 2));
        assert!(quality_checked_at_is_stale(Some(&stale), &now, 2));
        assert!(quality_checked_at_is_stale(Some("invalid"), &now, 2));
    }

    #[test]
    fn critical_unlock_transport_errors_stop_after_retry_budget_until_stale() {
        let now = chrono::Utc::now();
        let mut proxy = proxy_with_quality(Some(now.to_rfc3339()), MAX_INCOMPLETE_RETRIES);
        proxy.quality.as_mut().unwrap().ip_address = Some("203.0.113.10".into());
        proxy.quality.as_mut().unwrap().country = Some("US".into());
        proxy.quality.as_mut().unwrap().ip_type = Some("Residential".into());
        proxy.quality.as_mut().unwrap().risk_level = "Low".into();
        proxy.quality.as_mut().unwrap().details = Some(serde_json::json!({
            "schema_version": QUALITY_SCHEMA_VERSION,
            "unlock": {
                "google": {"status": "error", "available": null},
                "chatgpt": {"status": "available", "available": true}
            }
        }));

        assert!(!needs_quality_check(&proxy, &now, 24));
    }

    #[test]
    fn incomplete_quality_respects_persisted_retry_time() {
        let now = chrono::Utc::now();
        let mut proxy = proxy_with_quality(Some(now.to_rfc3339()), 1);
        proxy.quality.as_mut().unwrap().details = Some(serde_json::json!({
            "schema_version": QUALITY_SCHEMA_VERSION,
            "next_retry_at": (now + chrono::Duration::minutes(5)).to_rfc3339(),
            "unlock": {
                "google": {"status": "error", "available": null},
                "chatgpt": {"status": "available", "available": true}
            }
        }));
        assert!(!needs_quality_check(&proxy, &now, 24));

        proxy.quality.as_mut().unwrap().details.as_mut().unwrap()["next_retry_at"] =
            serde_json::json!((now - chrono::Duration::seconds(1)).to_rfc3339());
        assert!(needs_quality_check(&proxy, &now, 24));
    }

    #[test]
    fn explicit_unlock_unavailability_is_complete() {
        let details = serde_json::json!({
            "unlock": {
                "google": {"status": "unavailable", "available": false},
                "chatgpt": {"status": "available", "available": true}
            }
        });
        assert!(!critical_unlock_check_failed(Some(&details)));
    }

    #[test]
    fn unlock_transport_error_preserves_last_definitive_value() {
        assert!(merge_unlock_availability(None, Some(true)));
        assert!(!merge_unlock_availability(None, Some(false)));
        assert!(!merge_unlock_availability(Some(false), Some(true)));
        assert!(merge_unlock_availability(Some(true), Some(false)));
    }

    #[test]
    fn provider_ip_mismatch_rejects_metadata_from_other_exits() {
        let selected = select_provider_ip(
            Some("203.0.113.10"),
            Some("198.51.100.20"),
            Some("203.0.113.10"),
            Some("192.0.2.30"),
        );

        assert_eq!(selected.selected, Some("203.0.113.10"));
        assert!(selected.ippure_matches);
        assert!(!selected.ipinfo_matches);
        assert!(selected.ip_api_matches);
        assert!(selected.mismatch);
    }

    #[test]
    fn provider_ip_selection_falls_back_without_false_mismatch() {
        let selected = select_provider_ip(None, Some("198.51.100.20"), None, None);

        assert_eq!(selected.selected, Some("198.51.100.20"));
        assert!(!selected.ippure_matches);
        assert!(selected.ipinfo_matches);
        assert!(!selected.ip_api_matches);
        assert!(!selected.mismatch);
    }

    #[test]
    fn ippure_fields_drive_risk_and_native_metadata() {
        let body = serde_json::json!({
            "ip": "104.28.123.123",
            "asn": 13335,
            "asOrganization": "Cloudflare, Inc.",
            "country": "United States",
            "countryCode": "US",
            "fraudScore": 75,
            "isResidential": false,
            "isBroadcast": false
        });
        let parsed = parse_ippure(&body).unwrap();
        assert_eq!(parsed.ip.as_deref(), Some("104.28.123.123"));
        assert_eq!(parsed.asn, Some(13335));
        assert_eq!(parsed.fraud_score, Some(75.0));
        assert_eq!(parsed.is_residential, Some(false));

        let metadata = ippure_metadata(
            Some(&parsed),
            parsed.ip.as_deref(),
            parsed.country_code.as_deref(),
            false,
            Some("Datacenter"),
            0.75,
            risk_level(0.75),
        );
        assert_eq!(metadata["source"], "ippure");
        assert_eq!(metadata["asn"], 13335);
        assert_eq!(metadata["is_native"], true);
        assert_eq!(metadata["is_datacenter"], true);
        assert_eq!(metadata["fraud_score"], 75.0);
        assert_eq!(metadata["risk_level"], "High");
    }
}
