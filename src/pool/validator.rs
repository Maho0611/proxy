use crate::api::subscription::SyncMode;
use crate::pool::manager::ProxyStatus;
use crate::AppState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const EXIT_IP_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";

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

pub fn start_validation(state: Arc<AppState>) -> bool {
    if state
        .validation_running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    state
        .validation_progress
        .begin(None, None, None, "waiting-for-bindings");
    tokio::spawn(async move {
        let _running = RunningGuard {
            flag: &state.validation_running,
        };
        if let Err(error) = run_validation(state.clone()).await {
            state.validation_progress.fail(&error);
            tracing::error!("Manual validation failed: {error}");
        }
    });
    true
}

pub async fn validate_all(state: Arc<AppState>) -> Result<(), String> {
    let _running = match acquire_running_guard(&state.validation_running) {
        Some(guard) => guard,
        None => {
            tracing::info!("Validation already running, skipping duplicate trigger");
            return Ok(());
        }
    };

    run_validation(state.clone()).await
}

async fn run_validation(state: Arc<AppState>) -> Result<(), String> {
    let run_started = std::time::Instant::now();
    let db_calls_before = state.db.runtime_metrics().calls;
    state
        .validation_progress
        .begin(None, None, None, "waiting-for-bindings");

    // Serialize validations — wait if another is running, then check for remaining work
    let _lock = state.validation_lock.lock().await;
    state.validation_progress.set_phase("preparing");

    let total = state.db.count_all_proxies().unwrap_or(0);
    if total == 0 {
        tracing::info!("No proxies to validate");
        state.validation_progress.finish("没有可验活的代理");
        if let Err(error) = state
            .db
            .set_maintenance_completed_at(crate::db::SETTING_VALIDATION_LAST_COMPLETED_AT)
        {
            tracing::warn!("Failed to persist validation completion timestamp: {error}");
        }
        return Ok(());
    }

    let orphaned_cutoff = (chrono::Utc::now()
        - chrono::Duration::hours(state.config.subscription.orphaned_valid_grace_hours as i64))
    .to_rfc3339();
    match state.db.delete_orphaned_non_valid_before(&orphaned_cutoff) {
        Ok(count) if count > 0 => {
            tracing::info!(
                "Deleted {count} orphaned non-valid proxies past grace period (grace={}h)",
                state.config.subscription.orphaned_valid_grace_hours
            );
        }
        _ => {}
    }

    let concurrency = state.config.validation.concurrency;
    let timeout_duration = std::time::Duration::from_secs(state.config.validation.timeout_secs);
    let validation_url = state.config.validation.url.clone();
    let fallback_url = state.config.validation.fallback_url.clone();
    let max_proxies = state.config.singbox.max_proxies;
    let max_rounds = state.config.validation.max_rounds_per_run;
    let lease_owner = format!("validation-{}", uuid::Uuid::new_v4());
    let lease_seconds = validation_lease_seconds(
        state.config.validation.batch_size,
        concurrency,
        state.config.validation.timeout_secs,
    );

    let mut round = 0u32;
    let mut total_validated = 0usize;
    let mut total_exit_ip_unavailable = 0usize;

    loop {
        round += 1;
        state.validation_progress.set_round(round as usize);
        state.validation_progress.set_phase("binding");

        let claimed = state
            .db
            .claim_due_validation_proxy_records(
                state.config.validation.batch_size,
                &lease_owner,
                lease_seconds,
            )
            .map_err(|error| format!("领取验活任务失败: {error}"))?;
        if claimed.is_empty() {
            break;
        }
        let claimed_ids: Vec<_> = claimed
            .into_iter()
            .map(|(proxy, _)| proxy.id)
            .collect();
        let sync_result = crate::api::subscription::sync_proxy_bindings(
            &state,
            SyncMode::Targeted(claimed_ids.clone()),
        )
        .await;

        let selected_work: Vec<_> = sync_result
            .work_ids
            .iter()
            .filter_map(|id| state.pool.get(id))
            .collect();
        state.validation_progress.add_total(selected_work.len());

        let failed_to_bind: Vec<_> = selected_work
            .iter()
            .filter(|p| p.local_port.is_none())
            .cloned()
            .collect();

        let failed_binding_ids: Vec<_> = failed_to_bind
            .iter()
            .map(|proxy| proxy.id.clone())
            .collect();
        let recorded_binding_failures = match state
            .db
            .record_proxy_binding_failures(&failed_binding_ids)
        {
            Ok(failures) => failures.into_iter().collect::<std::collections::HashMap<_, _>>(),
            Err(error) => {
                tracing::warn!(
                    "Failed to persist {} binding failures as a batch: {error}",
                    failed_binding_ids.len()
                );
                state
                    .db
                    .release_validation_leases(&lease_owner, &failed_binding_ids, 60)
                    .ok();
                std::collections::HashMap::new()
            }
        };
        for proxy in &failed_to_bind {
            quarantine_proxy_after_binding_failure(
                &state,
                proxy,
                recorded_binding_failures
                    .get(&proxy.id)
                    .copied()
                    .unwrap_or(0),
            );
            state.validation_progress.advance(false);
        }

        // Collect only the untested proxies selected for this round that actually got bindings.
        let to_validate: Vec<_> = selected_work
            .iter()
            .filter(|p| p.local_port.is_some())
            .cloned()
            .collect();
        if to_validate.is_empty() {
            state
                .db
                .release_validation_leases(&lease_owner, &claimed_ids, 60)
                .ok();
            if selected_work.is_empty() {
                tracing::warn!(
                    "Validation stopped early: {} claimed definitions produced no binding candidates in round {round}",
                    claimed_ids.len()
                );
                break;
            }
            continue;
        }

        tracing::info!(
            "Validation round {round}: checking {} proxies (max_proxies={max_proxies})",
            to_validate.len()
        );
        state.validation_progress.set_phase("validating");

        // Validate this batch
        let round_summary = validate_batch(
            &to_validate,
            &validation_url,
            fallback_url.as_deref(),
            timeout_duration,
            concurrency,
            &state,
        )
        .await;
        let round_count = round_summary.completed;

        total_validated += round_count;
        total_exit_ip_unavailable += round_summary.exit_ip_unavailable;

        tracing::info!(
            "Round {round}: {round_count} proxies checked, {} reachable proxies had no measured exit IP",
            round_summary.exit_ip_unavailable
        );

        if round as usize >= max_rounds {
            tracing::info!("Validation paused after {round} rounds (limit={max_rounds})");
            break;
        }
    }

    // Quarantine high-error proxies (once, after all rounds). They remain in
    // the inventory so a transient probe-provider outage cannot create a
    // delete -> subscription refresh -> revalidate loop. Scheduling already
    // excludes rows at or above the configured threshold.
    let threshold = state.config.validation.error_threshold;
    let high_error_targets: Vec<_> = state
        .pool
        .get_all()
        .into_iter()
        .filter(|proxy| proxy.error_count >= threshold)
        .collect();
    for proxy in &high_error_targets {
        crate::bindings::cleanup_proxy_binding(&state, &proxy.id, proxy.local_port).await;
        state.binding_usage.remove(&proxy.id);
        state.pool.remove(&proxy.id);
    }
    if !high_error_targets.is_empty() {
        tracing::info!(
            "Quarantined {} proxies at or above error threshold {}; records were retained",
            high_error_targets.len(),
            threshold
        );
    }

    // Final assignment: normal mode (Valid gets priority for serving traffic)
    let _ = crate::api::subscription::sync_proxy_bindings(&state, SyncMode::Normal).await;
    if let Err(error) = crate::selection::rebuild(state.as_ref()) {
        tracing::warn!("Failed to rebuild selection snapshot after validation: {error}");
    }
    crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
    crate::api::fetch::invalidate_stats_cache(state.as_ref());
    let reconciled = crate::fixed_proxy::reconcile_all(&state).await;
    if reconciled > 0 {
        tracing::info!("Reconciled {reconciled} fixed exits after validation");
    }

    let valid = state.db.count_valid_proxies().unwrap_or(0);
    let total = state.db.count_all_proxies().unwrap_or(0);
    let db_calls = state
        .db
        .runtime_metrics()
        .calls
        .saturating_sub(db_calls_before);
    tracing::info!(
        elapsed_ms = run_started.elapsed().as_secs_f64() * 1000.0,
        db_calls,
        rounds = round,
        total_exit_ip_unavailable,
        "Validation complete: {total_validated} checked, {valid}/{total} valid"
    );
    state.validation_progress.finish(format!(
        "验活完成：本次检查 {total_validated} 条线路，当前 {valid}/{total} 有效"
    ));
    if let Err(error) = state
        .db
        .set_maintenance_completed_at(crate::db::SETTING_VALIDATION_LAST_COMPLETED_AT)
    {
        tracing::warn!("Failed to persist validation completion timestamp: {error}");
    }

    Ok(())
}

/// Force a health validation for every distinct active proxy definition owned
/// by one subscription, regardless of its previous validation timestamp.
pub fn start_subscription_validation(
    state: Arc<AppState>,
    subscription_id: String,
    subscription_name: String,
) -> bool {
    if state
        .validation_running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    state.validation_progress.begin(
        Some(&subscription_id),
        Some(&subscription_name),
        None,
        "waiting-for-bindings",
    );
    tokio::spawn(async move {
        let _running = RunningGuard {
            flag: &state.validation_running,
        };
        if let Err(error) =
            run_subscription_validation(state.clone(), subscription_id, subscription_name).await
        {
            state.validation_progress.fail(&error);
            tracing::error!("Manual subscription validation failed: {error}");
        }
    });
    true
}

async fn run_subscription_validation(
    state: Arc<AppState>,
    subscription_id: String,
    subscription_name: String,
) -> Result<(), String> {
    state.validation_progress.begin(
        Some(&subscription_id),
        Some(&subscription_name),
        None,
        "waiting-for-bindings",
    );
    let _lock = state.validation_lock.lock().await;
    state.validation_progress.set_phase("preparing");

    let rows = match state.db.get_proxies_by_subscription(&subscription_id) {
        Ok(rows) => rows,
        Err(error) => {
            let message = format!("读取订阅代理失败: {error}");
            state.validation_progress.fail(&message);
            return Err(message);
        }
    };
    let mut seen_definitions = std::collections::HashSet::new();
    let target_ids: Vec<String> = rows
        .into_iter()
        .filter(|proxy| proxy.orphaned_at.is_none())
        .filter(|proxy| {
            seen_definitions.insert(crate::api::subscription::proxy_row_definition_key(proxy))
        })
        .map(|proxy| proxy.id)
        .collect();
    state.validation_progress.set_total(target_ids.len());

    if target_ids.is_empty() {
        state.validation_progress.finish("该订阅没有可验活的代理");
        return Ok(());
    }

    let concurrency = state.config.validation.concurrency;
    let timeout_duration = std::time::Duration::from_secs(state.config.validation.timeout_secs);
    let validation_url = state.config.validation.url.clone();
    let fallback_url = state.config.validation.fallback_url.clone();
    let batch_size = state.config.validation.batch_size.max(1);
    let mut total_validated = 0usize;

    for (index, target_batch) in target_ids.chunks(batch_size).enumerate() {
        state.validation_progress.set_round(index + 1);
        state.validation_progress.set_phase("binding");
        let sync_result = crate::api::subscription::sync_proxy_bindings(
            &state,
            SyncMode::Targeted(target_batch.to_vec()),
        )
        .await;
        let selected_work: Vec<_> = sync_result
            .work_ids
            .iter()
            .filter_map(|id| state.pool.get(id))
            .collect();

        for _ in 0..target_batch.len().saturating_sub(selected_work.len()) {
            state.validation_progress.advance(false);
        }
        let failed_to_bind: Vec<_> = selected_work
            .iter()
            .filter(|proxy| proxy.local_port.is_none())
            .cloned()
            .collect();
        let failed_binding_ids: Vec<_> = failed_to_bind
            .iter()
            .map(|proxy| proxy.id.clone())
            .collect();
        let recorded_binding_failures = match state
            .db
            .record_proxy_binding_failures(&failed_binding_ids)
        {
            Ok(failures) => failures.into_iter().collect::<std::collections::HashMap<_, _>>(),
            Err(error) => {
                tracing::warn!(
                    "Failed to persist {} subscription binding failures as a batch: {error}",
                    failed_binding_ids.len()
                );
                std::collections::HashMap::new()
            }
        };
        for proxy in &failed_to_bind {
            quarantine_proxy_after_binding_failure(
                &state,
                proxy,
                recorded_binding_failures
                    .get(&proxy.id)
                    .copied()
                    .unwrap_or(0),
            );
            state.validation_progress.advance(false);
        }

        let to_validate: Vec<_> = selected_work
            .into_iter()
            .filter(|proxy| proxy.local_port.is_some())
            .collect();
        state.validation_progress.set_phase("validating");
        let summary = validate_batch(
            &to_validate,
            &validation_url,
            fallback_url.as_deref(),
            timeout_duration,
            concurrency,
            &state,
        )
        .await;
        total_validated += summary.completed;
    }

    let _ = crate::api::subscription::sync_proxy_bindings(&state, SyncMode::Normal).await;
    if let Err(error) = crate::selection::rebuild(state.as_ref()) {
        tracing::warn!(
            "Failed to rebuild selection snapshot after subscription validation: {error}"
        );
    }
    crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
    crate::api::fetch::invalidate_stats_cache(state.as_ref());
    let reconciled = crate::fixed_proxy::reconcile_all(&state).await;
    if reconciled > 0 {
        tracing::info!("Reconciled {reconciled} fixed exits after subscription validation");
    }

    let progress = state.validation_progress.snapshot();
    state.validation_progress.finish(format!(
        "订阅“{subscription_name}”验活完成：检查 {total_validated} 条线路，通过 {}，未通过 {}",
        progress.succeeded, progress.failed
    ));
    Ok(())
}

fn quarantine_proxy_after_binding_failure(
    state: &Arc<AppState>,
    proxy: &crate::pool::manager::PoolProxy,
    failures: u32,
) {
    let threshold = state.config.validation.binding_failure_threshold.max(1);
    if failures < threshold {
        tracing::warn!(
            "Proxy {} failed to get binding ({failures}/{threshold}); keeping it for a later round",
            proxy.name
        );
        return;
    }
    tracing::warn!(
        "Proxy {} failed to get binding {failures} consecutive times; quarantining it while retaining its record",
        proxy.name,
    );
    crate::selection::exclude_definition(state.as_ref(), proxy);
    state.binding_usage.remove(&proxy.id);
    state.pool.remove(&proxy.id);
}

/// Validate a batch of proxies concurrently, reusing one reqwest::Client per proxy port.
#[derive(Default)]
struct BatchSummary {
    completed: usize,
    succeeded: usize,
    failed: usize,
    exit_ip_unavailable: usize,
}

struct CompletedProbe {
    proxy_id: String,
    proxy_name: String,
    outcome: ProxyProbeOutcome,
}

enum ProxyProbeOutcome {
    Reachable {
        exit_ip: Option<String>,
        exit_ip_error: Option<String>,
    },
    Unreachable(String),
}

fn classify_probe_failure(error: &str) -> &'static str {
    let error = error.to_ascii_lowercase();
    if error.contains("deadline") || error.contains("timed out") || error.contains("timeout") {
        "timeout"
    } else if error.contains("certificate") || error.contains("tls") {
        "tls"
    } else if error.contains("expected http") || error.contains("http ") {
        "http_status"
    } else if error.contains("connect") || error.contains("dns") || error.contains("refused") {
        "connection"
    } else if error.contains("response") || error.contains("invalid") {
        "invalid_response"
    } else {
        "probe_failure"
    }
}

fn reachable_probe_outcome(exit_ip_result: Result<String, String>) -> ProxyProbeOutcome {
    match exit_ip_result {
        Ok(exit_ip) => ProxyProbeOutcome::Reachable {
            exit_ip: Some(exit_ip),
            exit_ip_error: None,
        },
        Err(error) => ProxyProbeOutcome::Reachable {
            exit_ip: None,
            exit_ip_error: Some(error),
        },
    }
}

async fn validate_batch(
    proxies: &[crate::pool::manager::PoolProxy],
    validation_url: &str,
    fallback_url: Option<&str>,
    timeout: std::time::Duration,
    concurrency: usize,
    state: &Arc<AppState>,
) -> BatchSummary {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = JoinSet::new();

    for proxy in proxies {
        let local_port = match proxy.local_port {
            Some(p) => p,
            None => continue,
        };

        let sem = semaphore.clone();
        let url = validation_url.to_string();
        let fallback_url = fallback_url.map(str::to_string);
        let proxy_id = proxy.id.clone();
        let proxy_name = proxy.name.clone();

        handles.spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let proxy_addr = format!("http://127.0.0.1:{local_port}");
            let outcome = probe_proxy(
                &proxy_addr,
                &url,
                fallback_url.as_deref(),
                timeout,
            )
            .await;
            CompletedProbe {
                proxy_id,
                proxy_name,
                outcome,
            }
        });
    }

    let mut summary = BatchSummary::default();
    let mut completed = Vec::new();
    while let Some(result) = handles.join_next().await {
        summary.completed += 1;
        match result {
            Ok(result) => completed.push(result),
            Err(error) => {
                tracing::warn!("Validation task failed to join: {error}");
                summary.failed += 1;
                state.validation_progress.advance(false);
            }
        }
    }

    let outcomes: Vec<_> = completed
        .iter()
        .map(|probe| match &probe.outcome {
            ProxyProbeOutcome::Reachable {
                exit_ip,
                exit_ip_error,
            } => {
                crate::db::ProxyValidationOutcome {
                    source_id: probe.proxy_id.clone(),
                    is_valid: true,
                    error: exit_ip_error.clone(),
                    exit_ip: exit_ip.clone(),
                    failure_kind: exit_ip_error
                        .as_ref()
                        .map(|_| "exit_ip_unavailable".to_string()),
                }
            }
            ProxyProbeOutcome::Unreachable(error) => crate::db::ProxyValidationOutcome {
                source_id: probe.proxy_id.clone(),
                is_valid: false,
                error: Some(error.clone()),
                exit_ip: None,
                failure_kind: Some(classify_probe_failure(error).to_string()),
            },
        })
        .collect();

    let applied = match state
        .db
        .apply_validation_outcomes(&outcomes, state.config.validation.error_threshold)
    {
        Ok(applied) => applied,
        Err(error) => {
            tracing::warn!(
                "Failed to persist validation batch of {} probes: {error}",
                completed.len()
            );
            summary.failed += completed.len();
            for _ in &completed {
                state.validation_progress.advance(false);
            }
            return summary;
        }
    };

    for probe in &completed {
        let succeeded = matches!(&probe.outcome, ProxyProbeOutcome::Reachable { .. });
        match &probe.outcome {
            ProxyProbeOutcome::Reachable {
                exit_ip: None,
                exit_ip_error: Some(error),
            } => {
                summary.exit_ip_unavailable += 1;
                tracing::warn!(
                    "Proxy {} is reachable but exit IP measurement failed: {error}",
                    probe.proxy_name
                );
            }
            ProxyProbeOutcome::Unreachable(error) => {
                tracing::debug!("Proxy {} failed validation: {error}", probe.proxy_name);
                if let Some(proxy) = state.pool.get(&probe.proxy_id) {
                    crate::selection::exclude_definition(state.as_ref(), &proxy);
                }
            }
            _ => {}
        }
        if succeeded {
            summary.succeeded += 1;
        } else {
            summary.failed += 1;
        }
        state.validation_progress.advance(succeeded);
    }

    for result in applied {
        if result.deleted_orphan {
            if let Some(proxy) = state.pool.get(&result.proxy_id) {
                crate::bindings::cleanup_proxy_binding(
                    state,
                    &result.proxy_id,
                    proxy.local_port,
                )
                .await;
            }
            state.binding_usage.remove(&result.proxy_id);
            state.pool.remove(&result.proxy_id);
            continue;
        }
        if result.is_valid {
            state.pool.set_status(&result.proxy_id, ProxyStatus::Valid);
            if let Some(exit_ip) = result.exit_ip {
                let quality = state
                    .pool
                    .get(&result.proxy_id)
                    .and_then(|proxy| proxy.quality)
                    .map(|mut quality| {
                        quality.ip_address = Some(exit_ip.clone());
                        quality
                    })
                    .unwrap_or(crate::pool::manager::ProxyQualityInfo {
                        ip_address: Some(exit_ip),
                        country: None,
                        ip_type: None,
                        is_residential: false,
                        chatgpt_accessible: false,
                        google_accessible: false,
                        risk_score: 1.0,
                        risk_level: "Unknown".to_string(),
                        checked_at: None,
                        details: None,
                        incomplete_retry_count: 0,
                    });
                state.pool.set_quality(&result.proxy_id, quality);
            }
        } else {
            state.pool.set_status(&result.proxy_id, ProxyStatus::Invalid);
        }
    }
    summary
}

fn build_probe_client(
    proxy_addr: &str,
    timeout: std::time::Duration,
) -> Result<reqwest::Client, String> {
    let proxy = reqwest::Proxy::all(proxy_addr).map_err(|e| format!("Proxy config error: {e}"))?;
    reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(timeout)
        .build()
        .map_err(|e| format!("Client build error: {e}"))
}

async fn probe_proxy(
    proxy_addr: &str,
    primary_url: &str,
    fallback_url: Option<&str>,
    timeout: std::time::Duration,
) -> ProxyProbeOutcome {
    let client = match build_probe_client(proxy_addr, timeout) {
        Ok(client) => client,
        Err(error) => return ProxyProbeOutcome::Unreachable(error),
    };
    let deadline = tokio::time::Instant::now() + timeout;
    // A successful trace establishes both reachability and the exit address.
    // Trace failure is only a measurement failure: reserve most of the total
    // budget for the independent 204 health probe before judging the proxy.
    let trace_budget = timeout
        .checked_div(3)
        .unwrap_or(timeout)
        .max(std::time::Duration::from_millis(250))
        .min(std::time::Duration::from_secs(5))
        .min(timeout);
    let trace_result = match tokio::time::timeout(
        trace_budget,
        request_exit_ip(&client, EXIT_IP_URL, true),
    )
    .await
    {
        Ok(Ok(exit_ip)) => return reachable_probe_outcome(Ok(exit_ip)),
        Ok(Err(error)) => Err(error),
        Err(_) => Err("Cloudflare trace measurement timed out".to_string()),
    };

    match tokio::time::timeout_at(
        deadline,
        validate_with_fallback(&client, primary_url, fallback_url),
    )
    .await
    {
        Ok(Ok(())) => reachable_probe_outcome(trace_result),
        Ok(Err(error)) => ProxyProbeOutcome::Unreachable(error),
        Err(_) => ProxyProbeOutcome::Unreachable(
            "primary/fallback health probes exceeded the proxy-level deadline".into(),
        ),
    }
}

async fn request_exit_ip(
    client: &reqwest::Client,
    url: &str,
    cloudflare_trace: bool,
) -> Result<String, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    let body = response
        .text()
        .await
        .map_err(|e| format!("response read failed: {e}"))?;
    parse_exit_ip_response(&body, cloudflare_trace)
}

fn parse_exit_ip_response(body: &str, cloudflare_trace: bool) -> Result<String, String> {
    let value = if cloudflare_trace {
        body.lines()
            .find_map(|line| line.strip_prefix("ip="))
            .ok_or_else(|| "Cloudflare trace response has no ip field".to_string())?
    } else {
        body.trim()
    };
    value
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| "service returned an invalid address".to_string())
}

async fn validate_single(
    client: &reqwest::Client,
    target_url: &str,
) -> Result<(), String> {
    let resp = client
        .get(target_url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if resp.status() == reqwest::StatusCode::NO_CONTENT {
        Ok(())
    } else {
        Err(format!("Expected HTTP 204, got {}", resp.status()))
    }
}

async fn validate_with_fallback(
    client: &reqwest::Client,
    primary_url: &str,
    fallback_url: Option<&str>,
) -> Result<(), String> {
    let primary = validate_single(client, primary_url).await;
    match (
        primary,
        fallback_url.filter(|url| !url.is_empty() && *url != primary_url),
    ) {
        (Ok(()), _) => Ok(()),
        (Err(primary_error), Some(fallback)) => validate_single(client, fallback)
            .await
            .map_err(|fallback_error| {
                format!(
                    "primary probe failed ({primary_error}); fallback failed ({fallback_error})"
                )
            }),
        (Err(error), None) => Err(error),
    }
}

fn validation_lease_seconds(batch_size: usize, concurrency: usize, timeout_secs: u64) -> u64 {
    let batch_size = batch_size.max(1) as u64;
    let concurrency = concurrency.max(1) as u64;
    let waves = batch_size / concurrency + u64::from(batch_size % concurrency != 0);
    timeout_secs
        .saturating_mul(waves)
        .saturating_add(120)
        .max(180)
}

#[cfg(test)]
mod tests {
    use super::{
        classify_probe_failure, parse_exit_ip_response, reachable_probe_outcome,
        validation_lease_seconds, ProxyProbeOutcome,
    };

    #[test]
    fn validation_lease_covers_the_queued_batch() {
        assert_eq!(validation_lease_seconds(200, 10, 10), 320);
        assert_eq!(validation_lease_seconds(200, 0, 10), 2_120);
    }

    #[test]
    fn expected_status_is_exact() {
        assert_eq!(reqwest::StatusCode::NO_CONTENT.as_u16(), 204);
        assert_ne!(reqwest::StatusCode::OK.as_u16(), 204);
    }

    #[test]
    fn probe_failures_are_classified_for_health_scheduling() {
        assert_eq!(classify_probe_failure("request timed out"), "timeout");
        assert_eq!(classify_probe_failure("TLS certificate rejected"), "tls");
        assert_eq!(
            classify_probe_failure("Expected HTTP 204, got 503"),
            "http_status"
        );
        assert_eq!(classify_probe_failure("connection refused"), "connection");
        assert_eq!(classify_probe_failure("invalid response body"), "invalid_response");
    }

    #[test]
    fn exit_ip_parser_accepts_cloudflare_trace_and_plain_fallback() {
        assert_eq!(
            parse_exit_ip_response("fl=1\nip=203.0.113.8\nloc=US\n", true).unwrap(),
            "203.0.113.8"
        );
        assert_eq!(
            parse_exit_ip_response("2001:db8::1\n", false).unwrap(),
            "2001:db8::1"
        );
        assert!(parse_exit_ip_response("loc=US\n", true).is_err());
    }

    #[test]
    fn exit_ip_failure_does_not_turn_a_reachable_proxy_into_a_health_failure() {
        let outcome = reachable_probe_outcome(Err("provider unavailable".into()));
        assert!(matches!(
            outcome,
            ProxyProbeOutcome::Reachable {
                exit_ip: None,
                exit_ip_error: Some(_)
            }
        ));
    }
}
