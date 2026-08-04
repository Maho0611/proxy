use crate::db::ProxyQuality;
use crate::pool::manager::{PoolProxy, ProxyQualityInfo};
use crate::AppState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::Instant;

/// Incomplete quality data can be retried at most this many times.
pub(crate) const MAX_INCOMPLETE_RETRIES: u8 = 2;
pub(crate) const QUALITY_SCHEMA_VERSION: u8 = 2;

/// ip-api.com rate limiter: max 40 requests/minute (free tier limit is 45).
struct RateLimiter {
    last_call: Mutex<Instant>,
    min_interval: std::time::Duration,
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
            last_call: Mutex::new(Instant::now() - std::time::Duration::from_secs(60)),
            min_interval: std::time::Duration::from_millis(60_000 / calls_per_minute as u64),
        }
    }

    async fn wait(&self) {
        let mut last = self.last_call.lock().await;
        let elapsed = last.elapsed();
        if elapsed < self.min_interval {
            tokio::time::sleep(self.min_interval - elapsed).await;
        }
        *last = Instant::now();
    }
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

    let now = chrono::Utc::now();
    let mut total_checked = 0usize;
    let rate_limiter = Arc::new(RateLimiter::new(40));
    let stale_hours = state.config.quality.stale_hours.max(1);
    let max_checks = state.config.quality.max_checks_per_run.max(1);

    // Hold lock only for short binding-selection work.
    let to_check = {
        let _lock = state.validation_lock.lock().await;
        let stale_before = (now - chrono::Duration::hours(stale_hours as i64)).to_rfc3339();
        let due = state
            .db
            .get_due_quality_proxy_records(
                max_checks,
                &stale_before,
                MAX_INCOMPLETE_RETRIES,
                QUALITY_SCHEMA_VERSION,
            )
            .map_err(|e| format!("Failed to load quality-check candidates: {e}"))?;

        if due.is_empty() {
            return Ok(0);
        }

        let sync_result = crate::api::subscription::sync_proxy_bindings(
            &state,
            crate::api::subscription::SyncMode::QualityCheck,
        )
        .await;

        sync_result
            .selected_ids
            .iter()
            .filter_map(|id| state.pool.get(id))
            .filter(|p| p.status == crate::pool::manager::ProxyStatus::Valid)
            .filter(|p| p.local_port.is_some())
            .filter(|p| needs_quality_check(p, &now, stale_hours))
            .take(max_checks)
            .collect::<Vec<PoolProxy>>()
    };

    if !to_check.is_empty() {
        tracing::info!(
            "Quality check: checking {} proxies this run (limit={max_checks}, stale_after={}h)",
            to_check.len(),
            stale_hours,
        );
        total_checked += check_batch(&to_check, &state, &rate_limiter).await;
    } else {
        tracing::info!(
            "Quality check: due proxies exist but none received active bindings this round"
        );
    }

    let _lock = state.validation_lock.lock().await;
    let _ = crate::api::subscription::sync_proxy_bindings(
        &state,
        crate::api::subscription::SyncMode::Normal,
    )
    .await;

    if total_checked > 0 {
        crate::api::fetch::invalidate_stats_cache(state.as_ref());
        crate::api::sub_export::invalidate_subscription_export_cache(state.as_ref());
        let reconciled = crate::fixed_proxy::reconcile_all(&state).await;
        if reconciled > 0 {
            tracing::info!("Reconciled {reconciled} fixed exits after quality checks");
        }
        tracing::info!("Quality check complete: {total_checked} proxies checked in this run");
    }

    Ok(total_checked)
}

/// Check a batch of proxies concurrently, respecting rate limits.
async fn check_batch(
    proxies: &[PoolProxy],
    state: &Arc<AppState>,
    rate_limiter: &Arc<RateLimiter>,
) -> usize {
    let semaphore = Arc::new(Semaphore::new(state.config.quality.concurrency));
    let mut handles = Vec::new();

    for proxy in proxies.iter().cloned() {
        let sem = semaphore.clone();
        let state = state.clone();
        let rl = rate_limiter.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let local_port = match proxy.local_port {
                Some(p) => p,
                None => return false,
            };

            let proxy_addr = format!("http://127.0.0.1:{local_port}");
            match check_single(&proxy_addr, &proxy, &rl).await {
                Ok(result) => {
                    let mut quality = result.quality;
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
                    if let Some(obj) = extra.as_object_mut() {
                        obj.insert(
                            "incomplete_retry_count".to_string(),
                            serde_json::json!(incomplete_retry_count),
                        );
                    }
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
                        checked_at: chrono::Utc::now().to_rfc3339(),
                    };
                    let duplicate_ids = match state
                        .db
                        .upsert_exact_duplicate_quality(&proxy.id, &db_quality)
                    {
                        Ok(ids) => ids,
                        Err(error) => {
                            tracing::warn!("Failed to save quality for {}: {error}", proxy.name);
                            return false;
                        }
                    };
                    quality.incomplete_retry_count = incomplete_retry_count;
                    for id in duplicate_ids {
                        state.pool.set_quality(&id, quality.clone());
                    }
                    true
                }
                Err(e) => {
                    tracing::warn!("Quality check failed for {}: {e}", proxy.name);
                    false
                }
            }
        });
        handles.push(handle);
    }

    let mut count = 0;
    for handle in handles {
        if matches!(handle.await, Ok(true)) {
            count += 1;
        }
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

            // Fresh but incomplete data gets a small immediate retry budget.
            if quality_is_incomplete(q) {
                return q.incomplete_retry_count < MAX_INCOMPLETE_RETRIES;
            }

            false
        }
    }
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

    // IPPure is queried first. Legacy providers are contacted only for
    // fields omitted by the public endpoint, avoiding unnecessary traffic
    // and rate-limit noise when IPPure returns a complete record.
    let ippure_result = query_ippure(&client).await;
    let need_ip_api = ippure_result
        .as_ref()
        .map(|result| {
            result.ip.is_none() || result.country_code.is_none() || result.fraud_score.is_none()
        })
        .unwrap_or(true);
    let need_ipinfo = ippure_result
        .as_ref()
        .map(|result| {
            result.ip.is_none()
                || result.country_code.is_none()
                || (result.is_residential.is_none() && result.is_datacenter.is_none())
        })
        .unwrap_or(true);
    let (ipapi_result, ipinfo_result, unlock_report) = tokio::join!(
        async {
            if need_ip_api {
                rate_limited_ip_api(&client, rate_limiter).await
            } else {
                None
            }
        },
        async {
            if need_ipinfo {
                query_ipinfo(&client).await
            } else {
                None
            }
        },
        crate::quality::unlock::check_all(&client),
    );

    let ippure_ok = ippure_result.is_some();
    let ip_api_ok = ipapi_result.is_some();
    let ipinfo_ok = ipinfo_result.is_some();

    // Merge IP info: prefer ipinfo.io for org detail, fall back to ip-api.com for IP/country
    let validation_ip = proxy
        .quality
        .as_ref()
        .and_then(|quality| quality.ip_address.clone());
    let (ipinfo_ip, ipinfo_country, ipinfo_type, ipinfo_residential) =
        ipinfo_result.unwrap_or((None, None, None, false));
    let ip_address = ippure_result
        .as_ref()
        .and_then(|result| result.ip.clone())
        .or(ipinfo_ip)
        .or_else(|| ipapi_result.as_ref().and_then(|result| result.ip.clone()))
        .or(validation_ip);
    let country = ippure_result
        .as_ref()
        .and_then(|result| result.country_code.clone())
        .or(ipinfo_country)
        .or_else(|| {
            ipapi_result
                .as_ref()
                .and_then(|result| result.country.clone())
        });
    let ippure_residential = ippure_result
        .as_ref()
        .and_then(|result| result.is_residential);
    let ippure_datacenter = ippure_result
        .as_ref()
        .and_then(|result| result.is_datacenter);
    let mut is_residential = ippure_residential.unwrap_or(ipinfo_residential);
    let mut ip_type = match (ippure_residential, ippure_datacenter) {
        (Some(true), _) => Some("Residential".to_string()),
        (Some(false), _) | (_, Some(true)) => Some("Datacenter".to_string()),
        (_, Some(false)) => Some("Native/ISP".to_string()),
        _ => ipinfo_type,
    };

    // Prefer IPPure's 0-100 fraud score. ip-api.com's coarse proxy/hosting
    // matrix is retained only when IPPure omits fraudScore.
    let (fallback_risk_score, fallback_risk_level, is_hosting) = match &ipapi_result {
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
    let (risk_score, risk_level) = ippure_result
        .as_ref()
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
    let ip_details = ippure_metadata(
        ippure_result.as_ref(),
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
            ip_address,
            country,
            ip_type,
            is_residential,
            chatgpt_accessible: unlock_report.chatgpt_accessible,
            google_accessible: unlock_report.google_accessible,
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
            "ip": ip_details,
            "unlock": unlock_report.checks,
            "google_check": google_check,
            "chatgpt_check": chatgpt_check,
        }),
        google_detail,
        chatgpt_detail,
    })
}

/// Wraps query_ip_api with rate limiting to stay under free tier limits.
async fn rate_limited_ip_api(
    client: &reqwest::Client,
    rate_limiter: &RateLimiter,
) -> Option<IpApiResult> {
    rate_limiter.wait().await;
    query_ip_api(client).await
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
async fn query_ip_api(client: &reqwest::Client) -> Option<IpApiResult> {
    let url = "http://ip-api.com/json?fields=query,countryCode,proxy,hosting,status,message";
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
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
