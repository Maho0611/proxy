mod api;
mod bindings;
mod config;
mod db;
mod error;
mod fixed_proxy;
mod jobs;
mod parser;
mod pool;
mod proxy_account;
mod proxy_listener;
mod proxy_rotation;
mod quality;
mod selection;
mod singbox;

use arc_swap::ArcSwap;
use crate::config::AppConfig;
use crate::db::{
    Database, ProxyAccount, SubscriptionDuplicateStats, SubscriptionOverlap, User,
};
use crate::jobs::JobTracker;
use crate::pool::manager::ProxyPool;
use crate::singbox::process::SingboxManager;
use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use sysinfo::{Pid, System};
use tokio::sync::Mutex;

pub struct AppState {
    pub config: AppConfig,
    pub db: Database,
    pub pool: ProxyPool,
    pub singbox: Arc<Mutex<SingboxManager>>,
    pub binding_usage: DashMap<String, bindings::BindingUsage>,
    /// Cached relay clients keyed by both local port and immutable proxy
    /// definition. Ports are reused, so using the port alone can retain a
    /// pooled connection for the previous binding.
    pub relay_clients: DashMap<(u16, String), reqwest::Client>,
    /// Cached generated client subscription bodies keyed by selector/format.
    pub subscription_export_cache: DashMap<String, SubscriptionExportCacheEntry>,
    /// Immutable, precomputed selection index used by every new data-plane
    /// connection. Full proxy definitions are retained here so selection and
    /// on-demand binding require no database query.
    pub selection_snapshot: ArcSwap<selection::SelectionSnapshot>,
    /// Immediate circuit-breaker overlay for definitions that failed after
    /// the latest immutable snapshot was built.
    pub selection_unavailable_definitions: DashMap<String, std::time::Instant>,
    /// Short-lived aggregate dashboard cache; avoids repeated full-table scans.
    pub dashboard_stats_cache: DashMap<(), DashboardStatsCacheEntry>,
    /// Coalesces concurrent dashboard cache misses into one database query.
    pub dashboard_stats_cache_fill: Mutex<()>,
    /// Short-lived exact counts for filtered proxy-list views.
    pub proxy_list_count_cache: DashMap<String, ProxyListCountCacheEntry>,
    pub proxy_list_count_cache_fill: Mutex<()>,
    /// Lazy duplicate/overlap analysis for the subscription admin view.
    pub subscription_duplicate_cache: DashMap<(), SubscriptionDuplicateCacheEntry>,
    pub subscription_duplicate_cache_fill: Mutex<()>,
    pub subscription_duplicate_generation: AtomicU64,
    /// Auth cache: (api_key | session_id) → (User, expires_at_instant).
    pub auth_cache: DashMap<String, (User, tokio::time::Instant)>,
    /// Live proxy-account cache keyed by base username. Admin mutations update
    /// it synchronously so disable/delete/rotation take effect immediately.
    pub proxy_accounts: DashMap<String, ProxyAccount>,
    /// Throttles best-effort last_used_at writes for busy accounts.
    pub proxy_account_last_used: DashMap<String, tokio::time::Instant>,
    /// Timed-rotation sessions keyed by account, session ID, interval and filters.
    pub proxy_rotation_sessions: DashMap<String, Arc<proxy_rotation::RotationSession>>,
    /// Per-slot locks make fixed-exit replacement converge under concurrent use.
    pub fixed_proxy_slot_locks: DashMap<String, Arc<Mutex<()>>>,
    /// Serializes binding changes during validation/quality work.
    pub validation_lock: Mutex<()>,
    /// Prevents duplicate validation runs from being queued/spawned.
    pub validation_running: AtomicBool,
    /// Observable state for the current or most recent validation run.
    pub validation_progress: JobTracker,
    /// Prevents duplicate quality-check runs from being queued/spawned.
    pub quality_running: AtomicBool,
    /// Observable state for the current or most recent quality-check run.
    pub quality_progress: JobTracker,
}

#[derive(Debug, Clone)]
pub struct SubscriptionExportCacheEntry {
    pub body: String,
    pub proxy_count: usize,
    pub expires_at: tokio::time::Instant,
}

#[derive(Debug, Clone)]
pub struct DashboardStatsCacheEntry {
    pub value: serde_json::Value,
    pub expires_at: tokio::time::Instant,
}

#[derive(Debug, Clone)]
pub struct ProxyListCountCacheEntry {
    pub filtered: usize,
    pub expires_at: tokio::time::Instant,
}

#[derive(Debug, Clone)]
pub struct SubscriptionDuplicateCacheEntry {
    pub stats: Vec<SubscriptionDuplicateStats>,
    pub overlaps: Vec<SubscriptionOverlap>,
    pub expires_at: tokio::time::Instant,
    pub generation: u64,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zenproxy=info,tower_http=info".into()),
        )
        .init();

    let config = AppConfig::load().expect("Failed to load config");
    tracing::info!(
        "Proxy starting on {}:{}",
        config.server.host,
        config.server.port
    );

    // Ensure data directory exists
    std::fs::create_dir_all("data").ok();

    // Initialize database
    let db = Database::new(
        &config.database.url,
        config.database.max_connections,
        std::time::Duration::from_millis(config.database.checkout_timeout_ms.max(100)),
    )
    .expect("Failed to initialize database");

    // Keep only the managed ready-set in memory on startup; the full inventory stays in DB.
    let pool = ProxyPool::new();
    pool.load_hot_from_db(
        &db,
        config
            .singbox
            .prebound_proxies
            .min(config.singbox.max_proxies),
    );

    // Clear stale local_port values — sing-box starts fresh, old ports have no bindings
    pool.clear_all_local_ports();
    db.clear_all_proxy_local_ports().ok();

    // Initialize SingboxManager and start with minimal config
    let mut manager =
        SingboxManager::new(config.singbox.clone(), config.validation.batch_size as u16);
    if let Err(e) = manager.start().await {
        tracing::warn!("Failed to start sing-box: {e}");
    }

    // Create initial bindings for valid proxies
    {
        let mut proxies = pool.get_valid_proxies();
        proxies.truncate(
            config
                .singbox
                .prebound_proxies
                .min(config.singbox.max_proxies),
        );
        if !proxies.is_empty() {
            let desired: Vec<(String, serde_json::Value)> = proxies
                .iter()
                .map(|p| (p.id.clone(), p.singbox_outbound.clone()))
                .collect();
            // No existing bindings at startup
            let assignments = manager.sync_bindings(&desired, &[]).await;
            for (id, port) in &assignments {
                pool.set_local_port(id, *port);
            }
            if let Err(error) = db.sync_proxy_local_ports(&assignments, &[]) {
                tracing::warn!("Failed to persist initial proxy bindings: {error}");
            }
            tracing::info!(
                "Created {} initial bindings for valid proxies (prebound limit={})",
                assignments.len(),
                config.singbox.prebound_proxies,
            );
        } else {
            tracing::info!("No valid proxies, sing-box running with minimal config");
        }
    }

    let singbox = Arc::new(Mutex::new(manager));

    let proxy_accounts = DashMap::new();
    for account in db
        .get_proxy_accounts()
        .expect("Failed to load proxy accounts")
    {
        proxy_accounts.insert(account.username.clone(), account);
    }

    let selection_snapshot = selection::SelectionSnapshot::load(&db)
        .expect("Failed to build initial proxy selection snapshot");

    let state = Arc::new(AppState {
        config: config.clone(),
        db,
        pool,
        singbox,
        binding_usage: DashMap::new(),
        relay_clients: DashMap::new(),
        subscription_export_cache: DashMap::new(),
        selection_snapshot: ArcSwap::from_pointee(selection_snapshot),
        selection_unavailable_definitions: DashMap::new(),
        dashboard_stats_cache: DashMap::new(),
        dashboard_stats_cache_fill: Mutex::new(()),
        proxy_list_count_cache: DashMap::new(),
        proxy_list_count_cache_fill: Mutex::new(()),
        subscription_duplicate_cache: DashMap::new(),
        subscription_duplicate_cache_fill: Mutex::new(()),
        subscription_duplicate_generation: AtomicU64::new(0),
        auth_cache: DashMap::new(),
        proxy_accounts,
        proxy_account_last_used: DashMap::new(),
        proxy_rotation_sessions: DashMap::new(),
        fixed_proxy_slot_locks: DashMap::new(),
        validation_lock: Mutex::new(()),
        validation_running: AtomicBool::new(false),
        validation_progress: JobTracker::new("validation"),
        quality_running: AtomicBool::new(false),
        quality_progress: JobTracker::new("quality-check"),
    });

    bindings::seed_managed_bindings(&state);

    // Start background tasks
    start_background_tasks(state.clone()).await;

    // Start proxy pool listeners (SOCKS5/HTTP)
    proxy_listener::start_proxy_listeners(state.clone());

    // Build router
    let app = api::router(state.clone());

    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("Proxy listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    // Cleanup: stop sing-box
    tracing::info!("Shutting down sing-box...");
    let mut mgr = state.singbox.lock().await;
    mgr.stop().await;
    tracing::info!("Proxy stopped");
}

async fn start_background_tasks(state: Arc<AppState>) {
    let state_clone = state.clone();
    // Safety-net refresh for missed invalidation events. Reads remain lock-free
    // because the rebuilt snapshot is swapped atomically after the DB scan.
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(selection::SNAPSHOT_REFRESH_SECS);
        loop {
            tokio::time::sleep(interval).await;
            if let Err(error) = selection::rebuild(state_clone.as_ref()) {
                tracing::warn!("Periodic selection snapshot rebuild failed: {error}");
            }
        }
    });

    let state_clone = state.clone();
    // Periodic validation
    tokio::spawn(async move {
        tracing::info!("Running startup proxy validation...");
        if let Err(e) = pool::validator::validate_all(state_clone.clone()).await {
            tracing::error!("Startup validation error: {e}");
        }

        let interval =
            std::time::Duration::from_secs(state_clone.config.validation.interval_mins * 60);
        loop {
            tokio::time::sleep(interval).await;
            tracing::info!("Running periodic proxy validation...");
            if let Err(e) = pool::validator::validate_all(state_clone.clone()).await {
                tracing::error!("Validation error: {e}");
            }
        }
    });

    let state_clone = state.clone();
    // Quality check — only checks proxies without quality data or with stale data
    tokio::spawn(async move {
        if state_clone.config.quality.interval_mins == 0 {
            tracing::info!("Automatic quality checks are disabled (quality.interval_mins=0)");
            return;
        }
        // Wait a bit on startup for proxies to be validated first
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let idle_interval = std::time::Duration::from_secs(
            state_clone.config.quality.interval_mins.saturating_mul(60),
        );
        loop {
            if let Err(e) = quality::checker::check_all(state_clone.clone()).await {
                tracing::error!("Quality check error: {e}");
            }
            tokio::time::sleep(idle_interval).await;
        }
    });

    let state_clone = state.clone();
    // Periodic idle binding cleanup for on-demand ports
    tokio::spawn(async move {
        if state_clone.config.singbox.binding_idle_secs == 0 {
            return;
        }
        let interval = std::time::Duration::from_secs(60);
        loop {
            tokio::time::sleep(interval).await;
            match bindings::cleanup_idle_bindings(state_clone.clone()).await {
                Ok(count) if count > 0 => {
                    tracing::info!("Cleaned up {count} idle on-demand bindings");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("Idle binding cleanup failed: {e}"),
            }
        }
    });

    let state_clone = state.clone();
    // Periodic session cleanup (every 6 hours)
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(6 * 60 * 60);
        loop {
            tokio::time::sleep(interval).await;
            tracing::info!("Cleaning up expired sessions...");
            match state_clone.db.cleanup_expired_sessions() {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("Cleaned up {count} expired sessions");
                    }
                }
                Err(e) => tracing::error!("Session cleanup error: {e}"),
            }
        }
    });

    let state_clone = state.clone();
    // Periodic auth cache cleanup (every 5 minutes)
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(5 * 60);
        loop {
            tokio::time::sleep(interval).await;
            let now = tokio::time::Instant::now();
            state_clone
                .auth_cache
                .retain(|_, (_, expires)| now < *expires);
        }
    });

    let state_clone = state.clone();
    // Periodic cleanup for inactive timed proxy-rotation sessions.
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(60);
        loop {
            tokio::time::sleep(interval).await;
            let count = proxy_rotation::cleanup_idle_sessions(&state_clone).await;
            if count > 0 {
                tracing::info!("Cleaned up {count} idle timed-rotation sessions");
            }
        }
    });

    let state_clone = state.clone();
    // Periodically repair fixed slots whose assigned upstream disappeared,
    // became invalid, changed country, or changed its measured exit address.
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(60);
        loop {
            tokio::time::sleep(interval).await;
            let count = fixed_proxy::reconcile_all(&state_clone).await;
            if count > 0 {
                tracing::info!("Reconciled {count} fixed proxy slots");
            }
        }
    });

    let state_clone = state.clone();
    // Periodic subscription auto-refresh (per-subscription schedule)
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(60);
        loop {
            tokio::time::sleep(interval).await;
            refresh_due_subscriptions(&state_clone).await;
        }
    });

    let state_clone = state.clone();
    // sing-box watchdog / scheduled restart safeguard
    tokio::spawn(async move {
        let interval_secs = state_clone.config.singbox.watchdog_interval_secs;
        if interval_secs == 0 {
            return;
        }
        let interval = std::time::Duration::from_secs(interval_secs);
        loop {
            tokio::time::sleep(interval).await;
            check_singbox_watchdog(&state_clone).await;
        }
    });
}

fn read_process_memory_mb(pid: u32) -> Option<u64> {
    let pid = Pid::from_u32(pid);
    let system = System::new_all();
    system
        .process(pid)
        .map(|process| process.memory() / 1024 / 1024)
}

async fn check_singbox_watchdog(state: &Arc<AppState>) {
    let restart_reason = {
        let mut mgr = state.singbox.lock().await;
        if !mgr.is_running() {
            Some("process exited".to_string())
        } else {
            let memory_restart_mb = state.config.singbox.memory_restart_mb;
            if memory_restart_mb > 0 {
                if let Some(memory_mb) = mgr
                    .process_id()
                    .and_then(read_process_memory_mb)
                    .filter(|memory_mb| *memory_mb >= memory_restart_mb)
                {
                    Some(format!(
                        "memory threshold exceeded: {memory_mb} MiB >= {memory_restart_mb} MiB"
                    ))
                } else if mgr.should_restart_for_interval() {
                    Some("scheduled interval".to_string())
                } else {
                    None
                }
            } else if mgr.should_restart_for_interval() {
                Some("scheduled interval".to_string())
            } else {
                None
            }
        }
    };

    let Some(reason) = restart_reason else {
        return;
    };
    let requires_quiet_restart = reason != "process exited";

    if requires_quiet_restart && state.binding_usage.iter().any(|entry| entry.in_flight > 0) {
        tracing::info!(
            "Skipping sing-box watchdog restart because active relay requests are in flight: {reason}"
        );
        return;
    }

    let _binding_lock = state.validation_lock.lock().await;

    if requires_quiet_restart && state.binding_usage.iter().any(|entry| entry.in_flight > 0) {
        tracing::info!(
            "Skipping sing-box watchdog restart after lock acquisition because relay requests resumed: {reason}"
        );
        return;
    }

    tracing::warn!("sing-box watchdog triggered restart: {reason}");

    {
        let mut mgr = state.singbox.lock().await;
        let restart_result = if mgr.is_running() {
            mgr.restart().await
        } else {
            mgr.start().await
        };

        if let Err(e) = restart_result {
            tracing::error!("sing-box watchdog failed to restart process: {e}");
            return;
        }
    }

    state.pool.clear_all_local_ports();
    state.db.clear_all_proxy_local_ports().ok();
    state.relay_clients.clear();

    let sync_result = crate::api::subscription::sync_proxy_bindings(
        state,
        crate::api::subscription::SyncMode::Normal,
    )
    .await;

    tracing::info!(
        "sing-box watchdog recovered process and re-synced {} bindings",
        sync_result.selected_ids.len()
    );
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install Ctrl+C handler");
    tracing::info!("Received shutdown signal");
}

async fn refresh_due_subscriptions(state: &Arc<AppState>) {
    let subs = match state.db.get_subscriptions() {
        Ok(subs) => subs,
        Err(e) => {
            tracing::error!("Auto-refresh: failed to get subscriptions: {e}");
            return;
        }
    };

    let default_refresh_interval_mins = state
        .db
        .get_subscription_default_refresh_interval_mins(
            state.config.subscription.auto_refresh_interval_mins,
        )
        .unwrap_or(state.config.subscription.auto_refresh_interval_mins);
    let now = chrono::Utc::now();
    let refreshable: Vec<_> = subs
        .into_iter()
        .filter(|sub| sub.is_refresh_due(default_refresh_interval_mins, &now))
        .collect();
    if refreshable.is_empty() {
        return;
    }

    tracing::info!("Auto-refreshing {} due subscriptions...", refreshable.len());

    let mut success = 0;
    let mut failed = 0;
    for sub in &refreshable {
        match api::subscription::refresh_subscription_core(state, sub).await {
            Ok(count) => {
                tracing::info!(
                    "Auto-refresh '{}': updated with {} proxies",
                    sub.name,
                    count
                );
                success += 1;
            }
            Err(e) => {
                tracing::error!("Auto-refresh '{}' failed: {e}", sub.name);
                failed += 1;
            }
        }
    }

    tracing::info!("Auto-refresh complete: {success} succeeded, {failed} failed");

    // Run validation once after all subscriptions are refreshed
    if success > 0 {
        let state2 = state.clone();
        tokio::spawn(async move {
            if let Err(e) = pool::validator::validate_all(state2).await {
                tracing::error!("Validation after auto-refresh failed: {e}");
            }
        });
    }
}
