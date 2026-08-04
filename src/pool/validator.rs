use crate::api::subscription::SyncMode;
use crate::pool::manager::ProxyStatus;
use crate::AppState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;

const EXIT_IP_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";
const EXIT_IP_FALLBACK_URL: &str = "https://api.ipify.org";

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

pub async fn validate_all(state: Arc<AppState>) -> Result<(), String> {
    let _running = match acquire_running_guard(&state.validation_running) {
        Some(guard) => guard,
        None => {
            tracing::info!("Validation already running, skipping duplicate trigger");
            return Ok(());
        }
    };

    // Serialize validations — wait if another is running, then check for remaining work
    let _lock = state.validation_lock.lock().await;

    let total = state.db.count_all_proxies().unwrap_or(0);
    if total == 0 {
        tracing::info!("No proxies to validate");
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

    let mut round = 0u32;
    let mut total_validated = 0usize;

    loop {
        round += 1;

        // Use validation-mode sorting: Untested get port priority over Valid
        let sync_result =
            crate::api::subscription::sync_proxy_bindings(&state, SyncMode::Validation).await;

        let selected_work: Vec<_> = sync_result
            .work_ids
            .iter()
            .filter_map(|id| state.pool.get(id))
            .collect();

        let failed_to_bind: Vec<_> = selected_work
            .iter()
            .filter(|p| p.local_port.is_none())
            .cloned()
            .collect();

        for proxy in &failed_to_bind {
            drop_proxy_after_binding_failure(&state, proxy).await;
        }

        // Collect only the untested proxies selected for this round that actually got bindings.
        let to_validate: Vec<_> = selected_work
            .iter()
            .filter(|p| p.local_port.is_some())
            .cloned()
            .collect();
        if to_validate.is_empty() {
            let remaining_untested = state.db.count_untested_proxies().unwrap_or(0);

            if selected_work.is_empty() {
                if remaining_untested > 0 {
                    tracing::warn!(
                        "Validation stopped early: no untested proxies received bindings in round {round}, {} untested remain",
                        remaining_untested
                    );
                }
                break;
            }

            continue;
        }

        tracing::info!(
            "Validation round {round}: checking {} proxies (max_proxies={max_proxies})",
            to_validate.len()
        );

        // Validate this batch
        let round_count = validate_batch(
            &to_validate,
            &validation_url,
            fallback_url.as_deref(),
            timeout_duration,
            concurrency,
            &state,
        )
        .await;

        total_validated += round_count;

        tracing::info!("Round {round}: {round_count} proxies checked");

        if round as usize >= max_rounds {
            tracing::info!("Validation paused after {round} rounds (limit={max_rounds})");
            break;
        }
    }

    // Cleanup high-error proxies (once, after all rounds)
    let threshold = state.config.validation.error_threshold;
    let high_error_targets: Vec<_> = state
        .pool
        .get_all()
        .into_iter()
        .filter(|proxy| proxy.error_count >= threshold)
        .collect();
    for proxy in &high_error_targets {
        crate::bindings::cleanup_proxy_binding(&state, &proxy.id, proxy.local_port).await;
    }
    match state.db.cleanup_high_error_proxies(threshold) {
        Ok(count) if count > 0 => {
            tracing::info!("Cleaned up {count} proxies exceeding error threshold");
            for proxy in &high_error_targets {
                state.binding_usage.remove(&proxy.id);
                state.pool.remove(&proxy.id);
            }
        }
        _ => {}
    }

    // Final assignment: normal mode (Valid gets priority for serving traffic)
    let _ = crate::api::subscription::sync_proxy_bindings(&state, SyncMode::Normal).await;
    crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
    crate::api::fetch::invalidate_stats_cache(state.as_ref());
    let reconciled = crate::fixed_proxy::reconcile_all(&state).await;
    if reconciled > 0 {
        tracing::info!("Reconciled {reconciled} fixed exits after validation");
    }

    let valid = state.db.count_valid_proxies().unwrap_or(0);
    let total = state.db.count_all_proxies().unwrap_or(0);
    tracing::info!(
        "Validation complete: {total_validated} checked in {round} rounds, {valid}/{total} valid"
    );

    Ok(())
}

async fn drop_proxy_after_binding_failure(
    state: &Arc<AppState>,
    proxy: &crate::pool::manager::PoolProxy,
) {
    let failures = match state.db.record_proxy_binding_failure(&proxy.id) {
        Ok(failures) => failures,
        Err(error) => {
            tracing::warn!(
                "Failed to record binding failure for {}: {error}",
                proxy.name
            );
            return;
        }
    };
    let threshold = state.config.validation.binding_failure_threshold.max(1);
    if failures < threshold {
        tracing::warn!(
            "Proxy {} failed to get binding ({failures}/{threshold}); keeping it for a later round",
            proxy.name
        );
        return;
    }
    tracing::warn!(
        "Proxy {} failed to get binding {failures} consecutive times; removing it",
        proxy.name,
    );
    crate::bindings::cleanup_proxy_binding(state, &proxy.id, proxy.local_port).await;
    state.binding_usage.remove(&proxy.id);
    state.pool.remove(&proxy.id);
    state.db.delete_proxy(&proxy.id).ok();
}

/// Validate a batch of proxies concurrently, reusing one reqwest::Client per proxy port.
async fn validate_batch(
    proxies: &[crate::pool::manager::PoolProxy],
    validation_url: &str,
    fallback_url: Option<&str>,
    timeout: std::time::Duration,
    concurrency: usize,
    state: &Arc<AppState>,
) -> usize {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(proxies.len());

    for proxy in proxies {
        let local_port = match proxy.local_port {
            Some(p) => p,
            None => continue,
        };

        let sem = semaphore.clone();
        let state = state.clone();
        let url = validation_url.to_string();
        let fallback_url = fallback_url.map(str::to_string);
        let proxy_id = proxy.id.clone();
        let proxy_name = proxy.name.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let proxy_addr = format!("http://127.0.0.1:{local_port}");
            let result =
                match validate_with_fallback(&proxy_addr, &url, fallback_url.as_deref(), timeout)
                    .await
                {
                    Ok(()) => detect_exit_ip(&proxy_addr, timeout).await,
                    Err(error) => Err(error),
                };

            match result {
                Ok(exit_ip) => {
                    let duplicate_ids = match state.db.update_exact_duplicate_validation(
                        &proxy_id,
                        true,
                        None,
                        Some(&exit_ip),
                    ) {
                        Ok(ids) => ids,
                        Err(error) => {
                            tracing::warn!(
                                "Proxy {proxy_name} passed validation but duplicate state could not be saved: {error}"
                            );
                            state.pool.set_status(&proxy_id, ProxyStatus::Invalid);
                            state
                                .db
                                .update_proxy_validation(
                                    &proxy_id,
                                    false,
                                    Some("Failed to persist detected exit IP"),
                                )
                                .ok();
                            return;
                        }
                    };
                    let quality = state
                        .pool
                        .get(&proxy_id)
                        .and_then(|p| p.quality)
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
                    for id in duplicate_ids {
                        state.pool.set_status(&id, ProxyStatus::Valid);
                        state.pool.set_quality(&id, quality.clone());
                    }
                }
                Err(e) => {
                    tracing::debug!("Proxy {proxy_name} failed validation: {e}");
                    let duplicate_ids = state
                        .db
                        .update_exact_duplicate_validation(&proxy_id, false, Some(&e), None)
                        .unwrap_or_else(|error| {
                            tracing::warn!("Failed to sync duplicate validation state: {error}");
                            vec![proxy_id.clone()]
                        });
                    for id in &duplicate_ids {
                        state.pool.set_status(id, ProxyStatus::Invalid);
                    }
                    let orphaned_ids: Vec<_> = duplicate_ids
                        .iter()
                        .filter_map(|id| {
                            state
                                .db
                                .delete_proxy_if_orphaned(id)
                                .unwrap_or(false)
                                .then(|| id.clone())
                        })
                        .collect();
                    if orphaned_ids.iter().any(|id| id == &proxy_id) {
                        crate::bindings::cleanup_proxy_binding(&state, &proxy_id, Some(local_port))
                            .await;
                    }
                    for id in orphaned_ids {
                        state.binding_usage.remove(&id);
                        state.pool.remove(&id);
                    }
                }
            }
        });
        handles.push(handle);
    }

    let mut count = 0;
    for handle in handles {
        if handle.await.is_ok() {
            count += 1;
        }
    }
    count
}

async fn detect_exit_ip(proxy_addr: &str, timeout: std::time::Duration) -> Result<String, String> {
    let proxy = reqwest::Proxy::all(proxy_addr).map_err(|e| format!("Proxy config error: {e}"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(timeout)
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|e| format!("Client build error: {e}"))?;
    match request_exit_ip(&client, EXIT_IP_URL, true).await {
        Ok(ip) => Ok(ip),
        Err(primary_error) => request_exit_ip(&client, EXIT_IP_FALLBACK_URL, false)
            .await
            .map_err(|fallback_error| {
                format!(
                    "Exit IP detection failed: primary ({primary_error}); fallback ({fallback_error})"
                )
            }),
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
    proxy_addr: &str,
    target_url: &str,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let proxy = reqwest::Proxy::all(proxy_addr).map_err(|e| format!("Proxy config error: {e}"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(timeout)
        .pool_max_idle_per_host(0) // don't keep idle connections
        .build()
        .map_err(|e| format!("Client build error: {e}"))?;

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
    proxy_addr: &str,
    primary_url: &str,
    fallback_url: Option<&str>,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let primary = validate_single(proxy_addr, primary_url, timeout).await;
    match (
        primary,
        fallback_url.filter(|url| !url.is_empty() && *url != primary_url),
    ) {
        (Ok(()), _) => Ok(()),
        (Err(primary_error), Some(fallback)) => validate_single(proxy_addr, fallback, timeout)
            .await
            .map_err(|fallback_error| {
                format!(
                    "primary probe failed ({primary_error}); fallback failed ({fallback_error})"
                )
            }),
        (Err(error), None) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_exit_ip_response;
    use crate::api::subscription::validation_batch_limits;

    #[test]
    fn expected_status_is_exact() {
        assert_eq!(reqwest::StatusCode::NO_CONTENT.as_u16(), 204);
        assert_ne!(reqwest::StatusCode::OK.as_u16(), 204);
    }

    #[test]
    fn validation_batch_has_non_starving_default_quotas() {
        assert_eq!(
            validation_batch_limits(300, 70, 20, 10, true),
            (210, 60, 30)
        );
        assert_eq!(validation_batch_limits(3, 70, 20, 10, true), (1, 1, 1));
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
}
