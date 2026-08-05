use base64::Engine;
use postgres::types::ToSql;
use postgres::{Client, Config, NoTls, Row};
use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const LATENCY_BUCKET_UPPER_US: [u64; 10] = [
    100,
    500,
    1_000,
    5_000,
    10_000,
    25_000,
    50_000,
    100_000,
    500_000,
    u64::MAX,
];

pub struct Database {
    pool: Pool<PostgresConnectionManager<NoTls>>,
    config: Config,
    checkout_timeout: Duration,
    overflow_lock: std::sync::Mutex<()>,
    timings: DatabaseTimingMetrics,
}

struct DatabaseTimingMetrics {
    calls: AtomicU64,
    wait_total_us: AtomicU64,
    query_total_us: AtomicU64,
    wait_max_us: AtomicU64,
    query_max_us: AtomicU64,
    wait_buckets: [AtomicU64; LATENCY_BUCKET_UPPER_US.len()],
    query_buckets: [AtomicU64; LATENCY_BUCKET_UPPER_US.len()],
}

impl Default for DatabaseTimingMetrics {
    fn default() -> Self {
        Self {
            calls: AtomicU64::new(0),
            wait_total_us: AtomicU64::new(0),
            query_total_us: AtomicU64::new(0),
            wait_max_us: AtomicU64::new(0),
            query_max_us: AtomicU64::new(0),
            wait_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            query_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DatabaseRuntimeMetrics {
    pub calls: u64,
    pub wait_avg_ms: f64,
    pub wait_p99_upper_ms: f64,
    pub wait_max_ms: f64,
    pub query_avg_ms: f64,
    pub query_p99_upper_ms: f64,
    pub query_max_ms: f64,
}

const SETTING_SUBSCRIPTION_DEFAULT_REFRESH_INTERVAL_MINS: &str =
    "subscription_auto_refresh_interval_mins";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub sub_type: String,
    pub url: Option<String>,
    pub content: Option<String>,
    pub proxy_count: i32,
    /// Number of parsable proxy records in the latest source payload, before
    /// exact-node deduplication.
    pub raw_proxy_count: i32,
    /// Exact duplicate records discarded before they can enter validation.
    pub duplicate_proxy_count: i32,
    pub refresh_interval_mins: Option<i32>,
    pub last_refresh_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Subscription {
    pub fn effective_refresh_interval_mins(
        &self,
        default_refresh_interval_mins: u64,
    ) -> Option<u64> {
        if self.url.is_none() {
            return None;
        }

        match self.refresh_interval_mins {
            Some(interval) if interval > 0 => Some(interval as u64),
            Some(_) => None,
            None if default_refresh_interval_mins > 0 => Some(default_refresh_interval_mins),
            None => None,
        }
    }

    pub fn is_refresh_due(
        &self,
        default_refresh_interval_mins: u64,
        now: &chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let Some(interval_mins) =
            self.effective_refresh_interval_mins(default_refresh_interval_mins)
        else {
            return false;
        };

        let anchor = self
            .last_refresh_at
            .as_deref()
            .or(Some(self.updated_at.as_str()))
            .or(Some(self.created_at.as_str()))
            .and_then(parse_rfc3339_utc);

        let Some(anchor) = anchor else {
            return true;
        };

        *now >= anchor + chrono::Duration::minutes(interval_mins as i64)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyRow {
    pub id: String,
    pub subscription_id: String,
    pub name: String,
    pub proxy_type: String,
    pub server: String,
    pub port: i32,
    pub config_json: String,
    pub is_valid: bool,
    pub local_port: Option<i32>,
    pub error_count: i32,
    pub last_error: Option<String>,
    pub last_validated: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub orphaned_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyQuality {
    pub proxy_id: String,
    pub ip_address: Option<String>,
    pub country: Option<String>,
    pub ip_type: Option<String>,
    pub is_residential: bool,
    pub chatgpt_accessible: bool,
    pub google_accessible: bool,
    pub risk_score: f64,
    pub risk_level: String,
    pub extra_json: Option<String>,
    pub checked_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub name: Option<String>,
    pub avatar_template: Option<String>,
    pub active: bool,
    pub trust_level: i32,
    pub silenced: bool,
    pub is_banned: bool,
    pub api_key: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyAccount {
    pub id: String,
    pub label: String,
    pub username: String,
    pub owner_user_id: Option<String>,
    pub enabled: bool,
    pub credential_version: i32,
    pub last_used_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FixedProxySlot {
    pub id: String,
    pub account_id: String,
    pub slot_key: String,
    pub label: String,
    pub country: String,
    pub proxy_type: Option<String>,
    pub residential: bool,
    pub chatgpt: bool,
    pub google: bool,
    pub proxy_id: String,
    pub exit_ip: String,
    pub included_in_subscription: bool,
    pub replacement_count: i32,
    pub last_replacement_reason: Option<String>,
    pub last_replaced_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct ProxyListQuery {
    pub page: usize,
    pub page_size: usize,
    /// Collapse rows with a measured exit IP to one canonical proxy. Admin
    /// inventory views leave this disabled so duplicate sources remain visible.
    pub unique_exit_ip: bool,
    pub cursor: Option<String>,
    pub direction: Option<String>,
    pub search: Option<String>,
    pub status: Option<String>,
    pub subscription_id: Option<String>,
    pub proxy_type: Option<String>,
    pub quality: Option<String>,
    pub sort: Option<String>,
    pub dir: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyListItem {
    pub id: String,
    pub subscription_id: String,
    pub name: String,
    pub proxy_type: String,
    pub server: String,
    pub port: i32,
    pub local_port: Option<i32>,
    pub status: String,
    pub error_count: i32,
    pub quality: Option<ProxyQuality>,
}

#[derive(Debug, Clone)]
pub struct ProxyListPage {
    pub proxies: Vec<ProxyListItem>,
    pub total: usize,
    pub filtered: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    pub next_cursor: Option<String>,
    pub prev_cursor: Option<String>,
    pub has_next: bool,
    pub has_previous: bool,
    pub counts_available: bool,
}

#[derive(Debug, Clone)]
pub struct ProxyValidationOutcome {
    pub source_id: String,
    pub is_valid: bool,
    pub error: Option<String>,
    pub exit_ip: Option<String>,
    pub failure_kind: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AppliedProxyValidation {
    pub proxy_id: String,
    pub is_valid: bool,
    pub exit_ip: Option<String>,
    pub deleted_orphan: bool,
}

#[derive(Debug, Clone)]
pub struct AppliedProxyQuality {
    pub proxy_id: String,
    pub source_id: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SubscriptionDuplicateStats {
    pub subscription_id: String,
    pub stored_nodes: i64,
    pub valid_nodes: i64,
    pub unique_endpoints: i64,
    pub duplicate_endpoint_nodes: i64,
    pub measured_exit_nodes: i64,
    pub unique_exit_ips: i64,
    pub duplicate_exit_ip_nodes: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SubscriptionOverlap {
    pub left_subscription_id: String,
    pub right_subscription_id: String,
    pub shared_exact_nodes: i64,
    pub shared_endpoints: i64,
    pub shared_exit_ips: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ProxyListCursor {
    sort: String,
    dir: String,
    value: String,
    id: String,
}

impl Database {
    pub fn new(
        url: &str,
        max_connections: u32,
        checkout_timeout: Duration,
    ) -> Result<Self, postgres::Error> {
        let mut config: Config = url.parse()?;
        config.application_name("zenproxy");
        // Keep one eager connection for the complete migration window. The
        // session advisory lock serializes expand/backfill/cutover across
        // multiple application instances and is released automatically if a
        // process exits mid-migration.
        let mut migration_guard = tokio::task::block_in_place(|| config.connect(NoTls))?;
        tokio::task::block_in_place(|| {
            migration_guard.batch_execute(
                "SELECT pg_advisory_lock(1514491472, 1380931673)",
            )
        })?;
        let manager = PostgresConnectionManager::new(config.clone(), NoTls);
        let pool = Pool::builder()
            .max_size(max_connections.clamp(1, 32))
            .connection_timeout(checkout_timeout)
            .build_unchecked(manager);
        let db = Database {
            pool,
            config,
            checkout_timeout,
            overflow_lock: std::sync::Mutex::new(()),
            timings: DatabaseTimingMetrics::default(),
        };
        let migration_result = (|| {
            db.migrate()?;
            db.backfill_definition_hashes()?;
            db.backfill_normalized_exit_quality()?;
            db.finalize_inventory_constraints()?;
            db.finalize_normalization_cutover()?;
            if let Err(error) = db.migrate_optional_search_indexes() {
                tracing::warn!(
                    "pg_trgm search indexes were not installed (database role may lack CREATE EXTENSION): {error}"
                );
            }
            Ok::<(), postgres::Error>(())
        })();
        let unlock_result = tokio::task::block_in_place(|| {
            migration_guard.batch_execute(
                "SELECT pg_advisory_unlock(1514491472, 1380931673)",
            )
        });
        migration_result?;
        unlock_result?;
        Ok(db)
    }

    fn with_conn<T>(
        &self,
        f: impl FnOnce(&mut Client) -> Result<T, postgres::Error>,
    ) -> Result<T, postgres::Error> {
        tokio::task::block_in_place(|| {
            let wait_started = Instant::now();
            let first_checkout = self.pool.get_timeout(self.checkout_timeout);
            let (waited, query_elapsed, result) = match first_checkout {
                Ok(mut conn) => {
                    let waited = wait_started.elapsed();
                    let query_started = Instant::now();
                    let result = f(&mut conn);
                    (waited, query_started.elapsed(), result)
                }
                Err(error) => {
                    tracing::warn!(
                        wait_ms = wait_started.elapsed().as_secs_f64() * 1000.0,
                        "database pool checkout failed ({error}); waiting for bounded overflow slot"
                    );
                    let guard = self
                        .overflow_lock
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    // A pooled connection commonly becomes available while
                    // waiting for the single overflow slot. Prefer it before
                    // opening the one permitted direct connection.
                    match self.pool.get_timeout(Duration::from_millis(100)) {
                        Ok(mut conn) => {
                            drop(guard);
                            let waited = wait_started.elapsed();
                            let query_started = Instant::now();
                            let result = f(&mut conn);
                            (waited, query_started.elapsed(), result)
                        }
                        Err(_) => {
                            let mut conn = self.config.connect(NoTls)?;
                            let waited = wait_started.elapsed();
                            let query_started = Instant::now();
                            let result = f(&mut conn);
                            let query_elapsed = query_started.elapsed();
                            drop(guard);
                            (waited, query_elapsed, result)
                        }
                    }
                }
            };
            self.timings.observe(waited, query_elapsed);
            if waited >= Duration::from_millis(50) {
                tracing::warn!(
                    wait_ms = waited.as_secs_f64() * 1000.0,
                    query_ms = query_elapsed.as_secs_f64() * 1000.0,
                    "database connection wait exceeded decision threshold"
                );
            }
            result
        })
    }

    pub fn runtime_metrics(&self) -> DatabaseRuntimeMetrics {
        self.timings.snapshot()
    }

    fn migrate(&self) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    sub_type TEXT NOT NULL,
                    url TEXT,
                    content TEXT,
                    proxy_count INTEGER NOT NULL DEFAULT 0,
                    raw_proxy_count INTEGER NOT NULL DEFAULT 0,
                    duplicate_proxy_count INTEGER NOT NULL DEFAULT 0,
                    refresh_interval_mins INTEGER,
                    last_refresh_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS proxies (
                    id TEXT PRIMARY KEY,
                    subscription_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    proxy_type TEXT NOT NULL,
                    server TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    config_json TEXT NOT NULL,
                    is_valid BOOLEAN NOT NULL DEFAULT FALSE,
                    local_port INTEGER,
                    error_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    last_validated TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    orphaned_at TEXT
                );

                ALTER TABLE proxies ADD COLUMN IF NOT EXISTS orphaned_at TEXT;
                ALTER TABLE proxies ADD COLUMN IF NOT EXISTS definition_hash BYTEA;
                ALTER TABLE proxies ADD COLUMN IF NOT EXISTS binding_failure_count INTEGER NOT NULL DEFAULT 0;
                ALTER TABLE proxies ADD COLUMN IF NOT EXISTS last_binding_failure TEXT;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS refresh_interval_mins INTEGER;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS last_refresh_at TEXT;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS raw_proxy_count INTEGER NOT NULL DEFAULT 0;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS duplicate_proxy_count INTEGER NOT NULL DEFAULT 0;

                -- Preserve duplicate inventories but release later duplicate
                -- rows from automatic refresh before enforcing URL ownership.
                WITH ranked_urls AS (
                    SELECT id,
                           ROW_NUMBER() OVER (
                               PARTITION BY BTRIM(url)
                               ORDER BY created_at ASC, id ASC
                           ) AS url_rank
                    FROM subscriptions
                    WHERE url IS NOT NULL AND BTRIM(url) <> ''
                )
                UPDATE subscriptions subscription
                SET url = NULL
                FROM ranked_urls ranked
                WHERE subscription.id = ranked.id AND ranked.url_rank > 1;
                CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_normalized_url
                    ON subscriptions ((BTRIM(url)))
                    WHERE url IS NOT NULL AND BTRIM(url) <> '';

                CREATE TABLE IF NOT EXISTS proxy_quality (
                    proxy_id TEXT PRIMARY KEY,
                    ip_address TEXT,
                    country TEXT,
                    ip_type TEXT,
                    is_residential BOOLEAN NOT NULL DEFAULT FALSE,
                    chatgpt_accessible BOOLEAN NOT NULL DEFAULT FALSE,
                    google_accessible BOOLEAN NOT NULL DEFAULT FALSE,
                    risk_score DOUBLE PRECISION NOT NULL DEFAULT 1.0,
                    risk_level TEXT NOT NULL DEFAULT 'Unknown',
                    extra_json TEXT,
                    checked_at TEXT NOT NULL
                );

                -- Expand/contract timestamp and JSON migration. Text columns
                -- remain as the compatibility API for this release while all
                -- scheduling/index work moves to typed mirrors maintained by
                -- triggers. A later cutover can rename the typed columns
                -- without a table rewrite or mixed-version deployment risk.
                CREATE OR REPLACE FUNCTION zenproxy_try_timestamptz(value TEXT)
                RETURNS TIMESTAMPTZ LANGUAGE plpgsql STABLE AS $$
                BEGIN
                    IF value IS NULL OR BTRIM(value) = '' THEN RETURN NULL; END IF;
                    RETURN value::timestamptz;
                EXCEPTION WHEN OTHERS THEN
                    RETURN NULL;
                END;
                $$;

                CREATE OR REPLACE FUNCTION zenproxy_rfc3339(value TIMESTAMPTZ)
                RETURNS TEXT LANGUAGE SQL IMMUTABLE AS $$
                    SELECT CASE WHEN value IS NULL THEN NULL ELSE
                        TO_CHAR(value AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
                    END
                $$;

                CREATE OR REPLACE FUNCTION zenproxy_try_jsonb(value TEXT)
                RETURNS JSONB LANGUAGE plpgsql IMMUTABLE AS $$
                BEGIN
                    IF value IS NULL OR BTRIM(value) = '' THEN RETURN NULL; END IF;
                    RETURN value::jsonb;
                EXCEPTION WHEN OTHERS THEN
                    RETURN NULL;
                END;
                $$;

                ALTER TABLE proxies ADD COLUMN IF NOT EXISTS created_at_ts TIMESTAMPTZ;
                ALTER TABLE proxies ADD COLUMN IF NOT EXISTS updated_at_ts TIMESTAMPTZ;
                ALTER TABLE proxies ADD COLUMN IF NOT EXISTS last_validated_ts TIMESTAMPTZ;
                ALTER TABLE proxies ADD COLUMN IF NOT EXISTS orphaned_at_ts TIMESTAMPTZ;
                ALTER TABLE proxies ADD COLUMN IF NOT EXISTS last_binding_failure_ts TIMESTAMPTZ;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS created_at_ts TIMESTAMPTZ;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS updated_at_ts TIMESTAMPTZ;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS last_refresh_at_ts TIMESTAMPTZ;
                ALTER TABLE proxy_quality ADD COLUMN IF NOT EXISTS checked_at_ts TIMESTAMPTZ;
                ALTER TABLE proxy_quality ADD COLUMN IF NOT EXISTS extra_jsonb JSONB;
                ALTER TABLE proxy_quality ADD COLUMN IF NOT EXISTS schema_version INTEGER NOT NULL DEFAULT 0;
                ALTER TABLE proxy_quality ADD COLUMN IF NOT EXISTS incomplete_retry_count INTEGER NOT NULL DEFAULT 0;

                UPDATE proxies SET
                    created_at_ts = COALESCE(created_at_ts, zenproxy_try_timestamptz(created_at)),
                    updated_at_ts = COALESCE(updated_at_ts, zenproxy_try_timestamptz(updated_at)),
                    last_validated_ts = COALESCE(last_validated_ts, zenproxy_try_timestamptz(last_validated)),
                    orphaned_at_ts = COALESCE(orphaned_at_ts, zenproxy_try_timestamptz(orphaned_at)),
                    last_binding_failure_ts = COALESCE(last_binding_failure_ts, zenproxy_try_timestamptz(last_binding_failure))
                WHERE created_at_ts IS NULL OR updated_at_ts IS NULL
                   OR (last_validated IS NOT NULL AND last_validated_ts IS NULL)
                   OR (orphaned_at IS NOT NULL AND orphaned_at_ts IS NULL)
                   OR (last_binding_failure IS NOT NULL AND last_binding_failure_ts IS NULL);

                UPDATE subscriptions SET
                    created_at_ts = COALESCE(created_at_ts, zenproxy_try_timestamptz(created_at)),
                    updated_at_ts = COALESCE(updated_at_ts, zenproxy_try_timestamptz(updated_at)),
                    last_refresh_at_ts = COALESCE(last_refresh_at_ts, zenproxy_try_timestamptz(last_refresh_at))
                WHERE created_at_ts IS NULL OR updated_at_ts IS NULL
                   OR (last_refresh_at IS NOT NULL AND last_refresh_at_ts IS NULL);

                UPDATE proxy_quality SET
                    checked_at_ts = COALESCE(checked_at_ts, zenproxy_try_timestamptz(checked_at)),
                    extra_jsonb = zenproxy_try_jsonb(extra_json),
                    schema_version = CASE
                        WHEN COALESCE(zenproxy_try_jsonb(extra_json)->>'schema_version', '') ~ '^[0-9]+$'
                        THEN (zenproxy_try_jsonb(extra_json)->>'schema_version')::INTEGER ELSE 0 END,
                    incomplete_retry_count = CASE
                        WHEN COALESCE(zenproxy_try_jsonb(extra_json)->>'incomplete_retry_count', '') ~ '^[0-9]+$'
                        THEN (zenproxy_try_jsonb(extra_json)->>'incomplete_retry_count')::INTEGER ELSE 0 END
                WHERE checked_at_ts IS NULL
                   OR extra_jsonb IS DISTINCT FROM zenproxy_try_jsonb(extra_json);

                CREATE OR REPLACE FUNCTION zenproxy_sync_proxy_timestamps()
                RETURNS TRIGGER LANGUAGE plpgsql AS $$
                BEGIN
                    NEW.created_at_ts := zenproxy_try_timestamptz(NEW.created_at);
                    NEW.updated_at_ts := zenproxy_try_timestamptz(NEW.updated_at);
                    NEW.last_validated_ts := zenproxy_try_timestamptz(NEW.last_validated);
                    NEW.orphaned_at_ts := zenproxy_try_timestamptz(NEW.orphaned_at);
                    NEW.last_binding_failure_ts := zenproxy_try_timestamptz(NEW.last_binding_failure);
                    RETURN NEW;
                END;
                $$;
                DROP TRIGGER IF EXISTS trg_zenproxy_proxy_timestamps ON proxies;
                CREATE TRIGGER trg_zenproxy_proxy_timestamps
                BEFORE INSERT OR UPDATE OF created_at, updated_at, last_validated, orphaned_at, last_binding_failure
                ON proxies FOR EACH ROW EXECUTE FUNCTION zenproxy_sync_proxy_timestamps();

                CREATE OR REPLACE FUNCTION zenproxy_sync_subscription_timestamps()
                RETURNS TRIGGER LANGUAGE plpgsql AS $$
                BEGIN
                    NEW.created_at_ts := zenproxy_try_timestamptz(NEW.created_at);
                    NEW.updated_at_ts := zenproxy_try_timestamptz(NEW.updated_at);
                    NEW.last_refresh_at_ts := zenproxy_try_timestamptz(NEW.last_refresh_at);
                    RETURN NEW;
                END;
                $$;
                DROP TRIGGER IF EXISTS trg_zenproxy_subscription_timestamps ON subscriptions;
                CREATE TRIGGER trg_zenproxy_subscription_timestamps
                BEFORE INSERT OR UPDATE OF created_at, updated_at, last_refresh_at
                ON subscriptions FOR EACH ROW EXECUTE FUNCTION zenproxy_sync_subscription_timestamps();

                CREATE OR REPLACE FUNCTION zenproxy_sync_quality_materialized()
                RETURNS TRIGGER LANGUAGE plpgsql AS $$
                DECLARE parsed JSONB;
                BEGIN
                    parsed := zenproxy_try_jsonb(NEW.extra_json);
                    NEW.checked_at_ts := zenproxy_try_timestamptz(NEW.checked_at);
                    NEW.extra_jsonb := parsed;
                    NEW.schema_version := CASE
                        WHEN COALESCE(parsed->>'schema_version', '') ~ '^[0-9]+$'
                        THEN (parsed->>'schema_version')::INTEGER ELSE 0 END;
                    NEW.incomplete_retry_count := CASE
                        WHEN COALESCE(parsed->>'incomplete_retry_count', '') ~ '^[0-9]+$'
                        THEN (parsed->>'incomplete_retry_count')::INTEGER ELSE 0 END;
                    RETURN NEW;
                END;
                $$;
                DROP TRIGGER IF EXISTS trg_zenproxy_quality_materialized ON proxy_quality;
                CREATE TRIGGER trg_zenproxy_quality_materialized
                BEFORE INSERT OR UPDATE OF extra_json, checked_at
                ON proxy_quality FOR EACH ROW EXECUTE FUNCTION zenproxy_sync_quality_materialized();

                CREATE OR REPLACE FUNCTION zenproxy_try_inet(value TEXT)
                RETURNS INET LANGUAGE plpgsql IMMUTABLE AS $$
                BEGIN
                    IF value IS NULL OR BTRIM(value) = '' THEN RETURN NULL; END IF;
                    RETURN value::inet;
                EXCEPTION WHEN OTHERS THEN
                    RETURN NULL;
                END;
                $$;

                CREATE TABLE IF NOT EXISTS proxy_definitions (
                    id TEXT PRIMARY KEY,
                    identity_version SMALLINT NOT NULL DEFAULT 1,
                    definition_hash BYTEA NOT NULL UNIQUE,
                    proxy_type TEXT NOT NULL,
                    server TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    config_json JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS subscription_proxies (
                    source_proxy_id TEXT PRIMARY KEY,
                    subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
                    definition_id TEXT NOT NULL REFERENCES proxy_definitions(id) ON DELETE RESTRICT,
                    display_name TEXT NOT NULL,
                    source_position INTEGER,
                    orphaned_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS proxy_health (
                    definition_id TEXT PRIMARY KEY REFERENCES proxy_definitions(id) ON DELETE CASCADE,
                    health_state TEXT NOT NULL DEFAULT 'untested'
                        CHECK (health_state IN ('untested', 'healthy', 'suspect', 'unhealthy')),
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    last_success_at TIMESTAMPTZ,
                    last_failure_at TIMESTAMPTZ,
                    next_check_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    failure_kind TEXT,
                    last_error TEXT,
                    lease_owner TEXT,
                    lease_until TIMESTAMPTZ,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS proxy_exit (
                    definition_id TEXT PRIMARY KEY REFERENCES proxy_definitions(id) ON DELETE CASCADE,
                    ip_address INET NOT NULL,
                    observed_at TIMESTAMPTZ NOT NULL,
                    observation_count BIGINT NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS exit_quality (
                    ip_address INET PRIMARY KEY,
                    country TEXT,
                    ip_type TEXT,
                    is_residential BOOLEAN NOT NULL DEFAULT FALSE,
                    chatgpt_accessible BOOLEAN NOT NULL DEFAULT FALSE,
                    google_accessible BOOLEAN NOT NULL DEFAULT FALSE,
                    risk_score DOUBLE PRECISION NOT NULL DEFAULT 1.0,
                    risk_level TEXT NOT NULL DEFAULT 'Unknown',
                    unlock_json JSONB,
                    extra_json JSONB,
                    checked_at TIMESTAMPTZ NOT NULL,
                    source_definition_id TEXT REFERENCES proxy_definitions(id) ON DELETE SET NULL
                );
                ALTER TABLE exit_quality ADD COLUMN IF NOT EXISTS extra_json JSONB;
                ALTER TABLE exit_quality ADD COLUMN IF NOT EXISTS chatgpt_accessible
                    BOOLEAN NOT NULL DEFAULT FALSE;
                ALTER TABLE exit_quality ADD COLUMN IF NOT EXISTS google_accessible
                    BOOLEAN NOT NULL DEFAULT FALSE;

                CREATE TABLE IF NOT EXISTS proxy_runtime (
                    definition_id TEXT PRIMARY KEY REFERENCES proxy_definitions(id) ON DELETE CASCADE,
                    local_port INTEGER,
                    binding_owner_id TEXT,
                    binding_failure_count INTEGER NOT NULL DEFAULT 0,
                    last_binding_failure TIMESTAMPTZ,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                ALTER TABLE proxy_runtime ADD COLUMN IF NOT EXISTS binding_owner_id TEXT;

                CREATE TABLE IF NOT EXISTS quality_check_leases (
                    quality_key TEXT PRIMARY KEY,
                    lease_owner TEXT NOT NULL,
                    lease_until TIMESTAMPTZ NOT NULL
                );

                -- Only incomplete checks without a usable exit IP live here.
                -- Exit-scoped quality remains normalized in exit_quality.
                CREATE TABLE IF NOT EXISTS quality_retry_state (
                    definition_id TEXT PRIMARY KEY
                        REFERENCES proxy_definitions(id) ON DELETE CASCADE,
                    extra_json JSONB NOT NULL,
                    checked_at TIMESTAMPTZ NOT NULL
                );

                INSERT INTO proxy_definitions (
                    id, identity_version, definition_hash, proxy_type, server, port,
                    config_json, created_at, updated_at
                )
                SELECT gen_random_uuid()::text, 1, selected.definition_hash,
                       selected.proxy_type, selected.server, selected.port,
                       COALESCE(zenproxy_try_jsonb(selected.config_json), '{}'::jsonb),
                       COALESCE(selected.created_at_ts, NOW()),
                       COALESCE(selected.updated_at_ts, NOW())
                FROM (
                    SELECT DISTINCT ON (definition_hash) *
                    FROM proxies
                    WHERE definition_hash IS NOT NULL
                    ORDER BY definition_hash, updated_at_ts DESC NULLS LAST, id
                ) selected
                ON CONFLICT (definition_hash) DO NOTHING;

                INSERT INTO subscription_proxies (
                    source_proxy_id, subscription_id, definition_id, display_name,
                    orphaned_at, created_at, updated_at
                )
                SELECT p.id, p.subscription_id, d.id, p.name, p.orphaned_at_ts,
                       COALESCE(p.created_at_ts, NOW()), COALESCE(p.updated_at_ts, NOW())
                FROM proxies p
                JOIN proxy_definitions d ON d.definition_hash = p.definition_hash
                ON CONFLICT (source_proxy_id) DO NOTHING;

                INSERT INTO proxy_health (
                    definition_id, health_state, consecutive_failures,
                    last_success_at, last_failure_at, next_check_at,
                    failure_kind, last_error, updated_at
                )
                SELECT DISTINCT ON (d.id)
                       d.id,
                       CASE
                           WHEN p.is_valid THEN 'healthy'
                           WHEN p.last_validated_ts IS NULL AND p.error_count = 0 THEN 'untested'
                           WHEN p.error_count >= 10 THEN 'unhealthy'
                           ELSE 'suspect'
                       END,
                       GREATEST(p.error_count, 0),
                       CASE WHEN p.is_valid THEN p.last_validated_ts END,
                       CASE WHEN NOT p.is_valid THEN p.last_validated_ts END,
                       CASE
                           WHEN p.last_validated_ts IS NULL THEN NOW()
                           WHEN p.is_valid THEN p.last_validated_ts + INTERVAL '30 minutes'
                           WHEN p.error_count >= 10 THEN NOW() + INTERVAL '12 hours'
                           ELSE NOW() + INTERVAL '5 minutes'
                       END,
                       CASE WHEN p.is_valid THEN NULL ELSE 'legacy_probe_failure' END,
                       p.last_error,
                       COALESCE(p.updated_at_ts, NOW())
                FROM proxies p
                JOIN proxy_definitions d ON d.definition_hash = p.definition_hash
                ORDER BY d.id, p.last_validated_ts DESC NULLS LAST, p.updated_at_ts DESC NULLS LAST, p.id
                ON CONFLICT (definition_id) DO NOTHING;

                INSERT INTO proxy_runtime (
                    definition_id, local_port, binding_owner_id, binding_failure_count,
                    last_binding_failure, updated_at
                )
                SELECT DISTINCT ON (d.id) d.id, p.local_port,
                       CASE WHEN p.local_port IS NULL THEN NULL ELSE p.id END,
                       p.binding_failure_count, p.last_binding_failure_ts,
                       COALESCE(p.updated_at_ts, NOW())
                FROM proxies p
                JOIN proxy_definitions d ON d.definition_hash = p.definition_hash
                ORDER BY d.id, CASE WHEN p.local_port IS NULL THEN 1 ELSE 0 END,
                         p.updated_at_ts DESC NULLS LAST, p.id
                ON CONFLICT (definition_id) DO NOTHING;

                UPDATE proxy_runtime runtime
                SET binding_owner_id = (
                    SELECT membership.source_proxy_id
                    FROM subscription_proxies membership
                    LEFT JOIN proxies legacy
                      ON legacy.id = membership.source_proxy_id
                    WHERE membership.definition_id = runtime.definition_id
                    ORDER BY CASE
                               WHEN legacy.local_port = runtime.local_port THEN 0 ELSE 1
                             END,
                             membership.updated_at DESC,
                             membership.source_proxy_id
                    LIMIT 1
                )
                WHERE runtime.local_port IS NOT NULL
                  AND runtime.binding_owner_id IS NULL;

                INSERT INTO proxy_exit (definition_id, ip_address, observed_at)
                SELECT DISTINCT ON (d.id) d.id, zenproxy_try_inet(q.ip_address),
                       COALESCE(q.checked_at_ts, NOW())
                FROM proxies p
                JOIN proxy_definitions d ON d.definition_hash = p.definition_hash
                JOIN proxy_quality q ON q.proxy_id = p.id
                WHERE zenproxy_try_inet(q.ip_address) IS NOT NULL
                ORDER BY d.id, q.checked_at_ts DESC NULLS LAST, p.id
                ON CONFLICT (definition_id) DO NOTHING;

                INSERT INTO exit_quality (
                    ip_address, country, ip_type, is_residential,
                    chatgpt_accessible, google_accessible, risk_score,
                    risk_level, unlock_json, extra_json, checked_at, source_definition_id
                )
                SELECT DISTINCT ON (zenproxy_try_inet(q.ip_address))
                       zenproxy_try_inet(q.ip_address), q.country, q.ip_type,
                       q.is_residential, q.chatgpt_accessible, q.google_accessible,
                       q.risk_score, q.risk_level,
                       q.extra_jsonb->'unlock', q.extra_jsonb,
                       COALESCE(q.checked_at_ts, NOW()), d.id
                FROM proxy_quality q
                JOIN proxies p ON p.id = q.proxy_id
                JOIN proxy_definitions d ON d.definition_hash = p.definition_hash
                WHERE zenproxy_try_inet(q.ip_address) IS NOT NULL
                ORDER BY zenproxy_try_inet(q.ip_address), q.checked_at_ts DESC NULLS LAST, p.id
                ON CONFLICT (ip_address) DO NOTHING;

                CREATE OR REPLACE FUNCTION zenproxy_sync_normalized_proxy()
                RETURNS TRIGGER LANGUAGE plpgsql AS $$
                DECLARE definition_id_value TEXT;
                BEGIN
                    IF NEW.definition_hash IS NULL THEN RETURN NEW; END IF;
                    INSERT INTO proxy_definitions (
                        id, identity_version, definition_hash, proxy_type, server,
                        port, config_json, created_at, updated_at
                    ) VALUES (
                        gen_random_uuid()::text, 1, NEW.definition_hash, NEW.proxy_type,
                        NEW.server, NEW.port,
                        COALESCE(zenproxy_try_jsonb(NEW.config_json), '{}'::jsonb),
                        COALESCE(NEW.created_at_ts, NOW()), COALESCE(NEW.updated_at_ts, NOW())
                    )
                    ON CONFLICT (definition_hash) DO UPDATE SET
                        proxy_type = EXCLUDED.proxy_type,
                        server = EXCLUDED.server,
                        port = EXCLUDED.port,
                        config_json = EXCLUDED.config_json,
                        updated_at = EXCLUDED.updated_at
                    RETURNING id INTO definition_id_value;

                    INSERT INTO subscription_proxies (
                        source_proxy_id, subscription_id, definition_id, display_name,
                        orphaned_at, created_at, updated_at
                    ) VALUES (
                        NEW.id, NEW.subscription_id, definition_id_value, NEW.name,
                        NEW.orphaned_at_ts, COALESCE(NEW.created_at_ts, NOW()),
                        COALESCE(NEW.updated_at_ts, NOW())
                    )
                    ON CONFLICT (source_proxy_id) DO UPDATE SET
                        subscription_id = EXCLUDED.subscription_id,
                        definition_id = EXCLUDED.definition_id,
                        display_name = EXCLUDED.display_name,
                        orphaned_at = EXCLUDED.orphaned_at,
                        updated_at = EXCLUDED.updated_at;
                    RETURN NEW;
                END;
                $$;
                DROP TRIGGER IF EXISTS trg_zenproxy_sync_normalized_proxy ON proxies;
                CREATE TRIGGER trg_zenproxy_sync_normalized_proxy
                AFTER INSERT OR UPDATE OF subscription_id, name, proxy_type, server, port,
                    config_json, definition_hash, orphaned_at, created_at, updated_at
                ON proxies FOR EACH ROW EXECUTE FUNCTION zenproxy_sync_normalized_proxy();

                CREATE OR REPLACE FUNCTION zenproxy_delete_normalized_membership()
                RETURNS TRIGGER LANGUAGE plpgsql AS $$
                BEGIN
                    DELETE FROM subscription_proxies WHERE source_proxy_id = OLD.id;
                    RETURN OLD;
                END;
                $$;
                DROP TRIGGER IF EXISTS trg_zenproxy_delete_normalized_membership ON proxies;
                CREATE TRIGGER trg_zenproxy_delete_normalized_membership
                AFTER DELETE ON proxies FOR EACH ROW
                EXECUTE FUNCTION zenproxy_delete_normalized_membership();

                CREATE OR REPLACE FUNCTION zenproxy_sync_normalized_health()
                RETURNS TRIGGER LANGUAGE plpgsql AS $$
                DECLARE definition_id_value TEXT;
                DECLARE state_value TEXT;
                DECLARE next_value TIMESTAMPTZ;
                BEGIN
                    SELECT id INTO definition_id_value FROM proxy_definitions
                    WHERE definition_hash = NEW.definition_hash;
                    IF definition_id_value IS NULL THEN RETURN NEW; END IF;
                    state_value := CASE
                        WHEN NEW.is_valid THEN 'healthy'
                        WHEN NEW.last_validated_ts IS NULL AND NEW.error_count = 0 THEN 'untested'
                        WHEN NEW.error_count >= 10 THEN 'unhealthy'
                        ELSE 'suspect'
                    END;
                    next_value := CASE
                        WHEN state_value = 'untested' THEN NOW()
                        WHEN state_value = 'healthy' THEN NOW() + INTERVAL '30 minutes'
                            + (RANDOM() * INTERVAL '5 minutes')
                        WHEN state_value = 'unhealthy' THEN NOW() + INTERVAL '12 hours'
                            + (RANDOM() * INTERVAL '30 minutes')
                        ELSE NOW() + CASE
                            WHEN NEW.error_count <= 1 THEN INTERVAL '5 minutes'
                            WHEN NEW.error_count = 2 THEN INTERVAL '15 minutes'
                            WHEN NEW.error_count = 3 THEN INTERVAL '60 minutes'
                            ELSE INTERVAL '180 minutes'
                        END
                    END;
                    INSERT INTO proxy_health (
                        definition_id, health_state, consecutive_failures,
                        last_success_at, last_failure_at, next_check_at,
                        failure_kind, last_error, lease_owner, lease_until, updated_at
                    ) VALUES (
                        definition_id_value, state_value, GREATEST(NEW.error_count, 0),
                        CASE WHEN NEW.is_valid THEN NEW.last_validated_ts END,
                        CASE WHEN NOT NEW.is_valid THEN NEW.last_validated_ts END,
                        next_value,
                        CASE WHEN NEW.is_valid THEN NULL ELSE 'probe_failure' END,
                        NEW.last_error, NULL, NULL, NOW()
                    )
                    ON CONFLICT (definition_id) DO UPDATE SET
                        health_state = EXCLUDED.health_state,
                        consecutive_failures = EXCLUDED.consecutive_failures,
                        last_success_at = COALESCE(EXCLUDED.last_success_at, proxy_health.last_success_at),
                        last_failure_at = COALESCE(EXCLUDED.last_failure_at, proxy_health.last_failure_at),
                        next_check_at = EXCLUDED.next_check_at,
                        failure_kind = EXCLUDED.failure_kind,
                        last_error = EXCLUDED.last_error,
                        lease_owner = NULL,
                        lease_until = NULL,
                        updated_at = NOW();
                    RETURN NEW;
                END;
                $$;
                DROP TRIGGER IF EXISTS trg_zenproxy_sync_normalized_health ON proxies;
                CREATE TRIGGER trg_zenproxy_sync_normalized_health
                AFTER INSERT OR UPDATE OF definition_hash, is_valid, error_count,
                    last_error, last_validated
                ON proxies FOR EACH ROW EXECUTE FUNCTION zenproxy_sync_normalized_health();

                CREATE OR REPLACE FUNCTION zenproxy_sync_exit_quality()
                RETURNS TRIGGER LANGUAGE plpgsql AS $$
                DECLARE definition_id_value TEXT;
                DECLARE parsed_ip INET;
                BEGIN
                    parsed_ip := zenproxy_try_inet(NEW.ip_address);
                    IF parsed_ip IS NULL THEN RETURN NEW; END IF;
                    SELECT d.id INTO definition_id_value
                    FROM proxies p JOIN proxy_definitions d
                      ON d.definition_hash = p.definition_hash
                    WHERE p.id = NEW.proxy_id;
                    IF definition_id_value IS NULL THEN RETURN NEW; END IF;
                    INSERT INTO proxy_exit (definition_id, ip_address, observed_at)
                    VALUES (definition_id_value, parsed_ip, COALESCE(NEW.checked_at_ts, NOW()))
                    ON CONFLICT (definition_id) DO UPDATE SET
                        ip_address = EXCLUDED.ip_address,
                        observed_at = EXCLUDED.observed_at,
                        observation_count = proxy_exit.observation_count + 1;
                    INSERT INTO exit_quality (
                        ip_address, country, ip_type, is_residential,
                        chatgpt_accessible, google_accessible, risk_score,
                        risk_level, unlock_json, extra_json, checked_at, source_definition_id
                    ) VALUES (
                        parsed_ip, NEW.country, NEW.ip_type, NEW.is_residential,
                        NEW.chatgpt_accessible, NEW.google_accessible,
                        NEW.risk_score, NEW.risk_level, NEW.extra_jsonb->'unlock',
                        NEW.extra_jsonb, COALESCE(NEW.checked_at_ts, NOW()), definition_id_value
                    )
                    ON CONFLICT (ip_address) DO UPDATE SET
                        country = EXCLUDED.country,
                        ip_type = EXCLUDED.ip_type,
                        is_residential = EXCLUDED.is_residential,
                        chatgpt_accessible = EXCLUDED.chatgpt_accessible,
                        google_accessible = EXCLUDED.google_accessible,
                        risk_score = EXCLUDED.risk_score,
                        risk_level = EXCLUDED.risk_level,
                        unlock_json = EXCLUDED.unlock_json,
                        extra_json = EXCLUDED.extra_json,
                        checked_at = EXCLUDED.checked_at,
                        source_definition_id = EXCLUDED.source_definition_id
                    WHERE exit_quality.checked_at <= EXCLUDED.checked_at;
                    RETURN NEW;
                END;
                $$;
                DROP TRIGGER IF EXISTS trg_zenproxy_sync_exit_quality ON proxy_quality;
                CREATE TRIGGER trg_zenproxy_sync_exit_quality
                AFTER INSERT OR UPDATE OF ip_address, country, ip_type, is_residential,
                    chatgpt_accessible, google_accessible, risk_score, risk_level,
                    extra_json, checked_at
                ON proxy_quality FOR EACH ROW EXECUTE FUNCTION zenproxy_sync_exit_quality();

                CREATE OR REPLACE FUNCTION zenproxy_sync_normalized_runtime()
                RETURNS TRIGGER LANGUAGE plpgsql AS $$
                DECLARE definition_id_value TEXT;
                BEGIN
                    SELECT id INTO definition_id_value FROM proxy_definitions
                    WHERE definition_hash = NEW.definition_hash;
                    IF definition_id_value IS NULL THEN RETURN NEW; END IF;
                    INSERT INTO proxy_runtime (
                        definition_id, local_port, binding_owner_id, binding_failure_count,
                        last_binding_failure, updated_at
                    ) VALUES (
                        definition_id_value, NEW.local_port,
                        CASE WHEN NEW.local_port IS NULL THEN NULL ELSE NEW.id END,
                        GREATEST(NEW.binding_failure_count, 0),
                        NEW.last_binding_failure_ts, NOW()
                    )
                    ON CONFLICT (definition_id) DO UPDATE SET
                        local_port = EXCLUDED.local_port,
                        binding_owner_id = EXCLUDED.binding_owner_id,
                        binding_failure_count = EXCLUDED.binding_failure_count,
                        last_binding_failure = EXCLUDED.last_binding_failure,
                        updated_at = NOW();
                    RETURN NEW;
                END;
                $$;
                DROP TRIGGER IF EXISTS trg_zenproxy_sync_normalized_runtime ON proxies;
                CREATE TRIGGER trg_zenproxy_sync_normalized_runtime
                AFTER INSERT OR UPDATE OF definition_hash, local_port,
                    binding_failure_count, last_binding_failure
                ON proxies FOR EACH ROW EXECUTE FUNCTION zenproxy_sync_normalized_runtime();

                CREATE OR REPLACE VIEW normalized_proxies AS
                SELECT membership.source_proxy_id AS id,
                       membership.subscription_id,
                       membership.display_name AS name,
                       definition.proxy_type,
                       definition.server,
                       definition.port,
                       definition.config_json::text AS config_json,
                       COALESCE(health.health_state = 'healthy', FALSE) AS is_valid,
                       runtime.local_port,
                       COALESCE(health.consecutive_failures, 0) AS error_count,
                       CASE
                           WHEN COALESCE(runtime.binding_failure_count, 0) > 0
                               THEN 'sing-box binding failed'
                           ELSE health.last_error
                       END AS last_error,
                       zenproxy_rfc3339(
                           CASE
                               WHEN health.last_success_at IS NULL THEN health.last_failure_at
                               WHEN health.last_failure_at IS NULL THEN health.last_success_at
                               ELSE GREATEST(health.last_success_at, health.last_failure_at)
                           END
                       ) AS last_validated,
                       zenproxy_rfc3339(membership.created_at) AS created_at,
                       zenproxy_rfc3339(GREATEST(
                           membership.updated_at,
                           definition.updated_at,
                           health.updated_at,
                           COALESCE(runtime.updated_at, membership.updated_at)
                       )) AS updated_at,
                       zenproxy_rfc3339(membership.orphaned_at) AS orphaned_at,
                       definition.definition_hash,
                       COALESCE(runtime.binding_failure_count, 0) AS binding_failure_count,
                       zenproxy_rfc3339(runtime.last_binding_failure) AS last_binding_failure,
                       membership.created_at AS created_at_ts,
                       GREATEST(
                           membership.updated_at,
                           definition.updated_at,
                           health.updated_at,
                           COALESCE(runtime.updated_at, membership.updated_at)
                       ) AS updated_at_ts,
                       CASE
                           WHEN health.last_success_at IS NULL THEN health.last_failure_at
                           WHEN health.last_failure_at IS NULL THEN health.last_success_at
                           ELSE GREATEST(health.last_success_at, health.last_failure_at)
                       END AS last_validated_ts,
                       membership.orphaned_at AS orphaned_at_ts,
                       runtime.last_binding_failure AS last_binding_failure_ts,
                       membership.definition_id,
                       runtime.binding_owner_id
                FROM subscription_proxies membership
                JOIN proxy_definitions definition ON definition.id = membership.definition_id
                LEFT JOIN proxy_health health ON health.definition_id = definition.id
                LEFT JOIN proxy_runtime runtime ON runtime.definition_id = definition.id;

                CREATE OR REPLACE VIEW normalized_proxy_quality AS
                SELECT membership.source_proxy_id AS proxy_id,
                       HOST(observed.ip_address) AS ip_address,
                       quality.country,
                       quality.ip_type,
                       COALESCE(quality.is_residential, FALSE) AS is_residential,
                       COALESCE(quality.chatgpt_accessible, FALSE)
                           AS chatgpt_accessible,
                       COALESCE(quality.google_accessible, FALSE)
                           AS google_accessible,
                       COALESCE(quality.risk_score, 1.0) AS risk_score,
                       COALESCE(quality.risk_level, 'Unknown') AS risk_level,
                       COALESCE(
                           quality.extra_json,
                           retry.extra_json,
                           jsonb_build_object('unlock', quality.unlock_json)
                       )::text AS extra_json,
                       zenproxy_rfc3339(
                           COALESCE(quality.checked_at, retry.checked_at, observed.observed_at)
                       ) AS checked_at,
                       COALESCE(
                           quality.checked_at, retry.checked_at, observed.observed_at
                       ) AS checked_at_ts,
                       COALESCE(
                           quality.extra_json,
                           retry.extra_json,
                           jsonb_build_object('unlock', quality.unlock_json)
                       ) AS extra_jsonb,
                       CASE
                           WHEN COALESCE(quality.extra_json, retry.extra_json)
                                    ->> 'schema_version' ~ '^[0-9]{1,9}$'
                           THEN (COALESCE(quality.extra_json, retry.extra_json)
                                    ->> 'schema_version')::integer
                           ELSE 0
                       END AS schema_version,
                       CASE
                           WHEN COALESCE(quality.extra_json, retry.extra_json)
                                    ->> 'incomplete_retry_count' ~ '^[0-9]{1,9}$'
                           THEN (COALESCE(quality.extra_json, retry.extra_json)
                                    ->> 'incomplete_retry_count')::integer
                           ELSE 0
                       END AS incomplete_retry_count,
                       membership.definition_id
                FROM subscription_proxies membership
                LEFT JOIN proxy_exit observed
                  ON observed.definition_id = membership.definition_id
                LEFT JOIN exit_quality quality ON quality.ip_address = observed.ip_address
                LEFT JOIN quality_retry_state retry
                  ON retry.definition_id = membership.definition_id
                WHERE observed.ip_address IS NOT NULL OR retry.definition_id IS NOT NULL;

                CREATE INDEX IF NOT EXISTS idx_subscription_proxies_definition
                    ON subscription_proxies(definition_id, subscription_id)
                    WHERE orphaned_at IS NULL;
                CREATE INDEX IF NOT EXISTS idx_subscription_proxies_subscription
                    ON subscription_proxies(subscription_id, orphaned_at, definition_id);
                CREATE INDEX IF NOT EXISTS idx_proxy_definitions_type
                    ON proxy_definitions(proxy_type, id);
                CREATE INDEX IF NOT EXISTS idx_proxy_health_due
                    ON proxy_health(next_check_at, definition_id)
                    WHERE lease_until IS NULL;
                CREATE INDEX IF NOT EXISTS idx_proxy_health_lease
                    ON proxy_health(lease_until) WHERE lease_until IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_proxy_health_due_lease
                    ON proxy_health(next_check_at, lease_until, definition_id);
                CREATE INDEX IF NOT EXISTS idx_quality_check_leases_until
                    ON quality_check_leases(lease_until);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_runtime_local_port
                    ON proxy_runtime(local_port) WHERE local_port IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_proxy_exit_ip
                    ON proxy_exit(ip_address, definition_id);
                CREATE INDEX IF NOT EXISTS idx_exit_quality_country_upper
                    ON exit_quality(UPPER(country), ip_address);
                CREATE INDEX IF NOT EXISTS idx_exit_quality_checked_at
                    ON exit_quality(checked_at, ip_address);

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    name TEXT,
                    avatar_template TEXT,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    trust_level INTEGER NOT NULL DEFAULT 0,
                    silenced BOOLEAN NOT NULL DEFAULT FALSE,
                    is_banned BOOLEAN NOT NULL DEFAULT FALSE,
                    api_key TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS proxy_accounts (
                    id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    username TEXT NOT NULL UNIQUE,
                    owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    credential_version INTEGER NOT NULL DEFAULT 1,
                    last_used_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS fixed_proxy_slots (
                    id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL REFERENCES proxy_accounts(id) ON DELETE CASCADE,
                    slot_key TEXT NOT NULL,
                    label TEXT NOT NULL,
                    country TEXT NOT NULL,
                    proxy_type TEXT,
                    residential BOOLEAN NOT NULL DEFAULT FALSE,
                    chatgpt BOOLEAN NOT NULL DEFAULT FALSE,
                    google BOOLEAN NOT NULL DEFAULT FALSE,
                    proxy_id TEXT NOT NULL,
                    exit_ip TEXT NOT NULL,
                    included_in_subscription BOOLEAN NOT NULL DEFAULT TRUE,
                    replacement_count INTEGER NOT NULL DEFAULT 0,
                    last_replacement_reason TEXT,
                    last_replaced_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(account_id, slot_key),
                    UNIQUE(account_id, exit_ip)
                );

                CREATE TABLE IF NOT EXISTS fixed_proxy_subscriptions (
                    account_id TEXT PRIMARY KEY REFERENCES proxy_accounts(id) ON DELETE CASCADE,
                    token_version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
                CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_accounts_owner_user_id
                    ON proxy_accounts(owner_user_id)
                    WHERE owner_user_id IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_proxy_accounts_username_enabled
                    ON proxy_accounts(username, enabled);
                CREATE INDEX IF NOT EXISTS idx_fixed_proxy_slots_account
                    ON fixed_proxy_slots(account_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_fixed_proxy_slots_proxy
                    ON fixed_proxy_slots(proxy_id);
                CREATE INDEX IF NOT EXISTS idx_proxies_subscription_id ON proxies(subscription_id);
                CREATE INDEX IF NOT EXISTS idx_proxies_definition_hash ON proxies(definition_hash);
                CREATE INDEX IF NOT EXISTS idx_proxies_definition_hash_current
                    ON proxies(definition_hash) WHERE orphaned_at IS NULL;
                CREATE INDEX IF NOT EXISTS idx_proxies_endpoint_subscription
                    ON proxies ((LOWER(server)), port, proxy_type, subscription_id)
                    WHERE orphaned_at IS NULL;
                CREATE INDEX IF NOT EXISTS idx_proxies_is_valid ON proxies(is_valid);
                CREATE INDEX IF NOT EXISTS idx_proxies_last_validated ON proxies(last_validated);
                CREATE INDEX IF NOT EXISTS idx_proxies_error_count ON proxies(error_count);
                CREATE INDEX IF NOT EXISTS idx_proxies_proxy_type ON proxies(proxy_type);
                CREATE INDEX IF NOT EXISTS idx_proxies_hot_selection
                    ON proxies(orphaned_at ASC, error_count ASC, last_validated DESC, updated_at DESC)
                    WHERE is_valid = TRUE;
                CREATE INDEX IF NOT EXISTS idx_proxies_hot_selection_ts
                    ON proxies(orphaned_at_ts ASC, error_count ASC, last_validated_ts DESC, updated_at_ts DESC)
                    WHERE is_valid = TRUE;
                CREATE INDEX IF NOT EXISTS idx_proxies_untested_selection
                    ON proxies(error_count ASC, created_at DESC)
                    WHERE is_valid = FALSE AND last_validated IS NULL;
                CREATE INDEX IF NOT EXISTS idx_proxies_current_untested_selection
                    ON proxies(error_count DESC, created_at ASC)
                    WHERE is_valid = FALSE
                      AND last_validated IS NULL
                      AND orphaned_at IS NULL;
                CREATE INDEX IF NOT EXISTS idx_proxies_invalid_retry
                    ON proxies(error_count ASC, updated_at DESC)
                    WHERE is_valid = FALSE AND last_validated IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_proxies_invalid_retry_ts
                    ON proxies(error_count ASC, updated_at_ts DESC)
                    WHERE is_valid = FALSE AND last_validated_ts IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_proxies_orphaned_at ON proxies(orphaned_at);
                CREATE INDEX IF NOT EXISTS idx_proxies_binding_retry
                    ON proxies(last_binding_failure)
                    WHERE binding_failure_count > 0;
                CREATE INDEX IF NOT EXISTS idx_proxy_quality_country ON proxy_quality(country);
                CREATE INDEX IF NOT EXISTS idx_proxy_quality_ip_address
                    ON proxy_quality(ip_address)
                    WHERE ip_address IS NOT NULL AND BTRIM(ip_address) <> '';
                CREATE INDEX IF NOT EXISTS idx_proxy_quality_chatgpt ON proxy_quality(chatgpt_accessible);
                CREATE INDEX IF NOT EXISTS idx_proxy_quality_google ON proxy_quality(google_accessible);
                CREATE INDEX IF NOT EXISTS idx_proxy_quality_residential ON proxy_quality(is_residential);
                CREATE INDEX IF NOT EXISTS idx_proxy_quality_due_v2
                    ON proxy_quality(schema_version, checked_at_ts, proxy_id);
                CREATE INDEX IF NOT EXISTS idx_proxy_quality_country_upper
                    ON proxy_quality(UPPER(country), proxy_id);
                CREATE INDEX IF NOT EXISTS idx_proxy_quality_unlock_retry
                    ON proxy_quality(checked_at_ts, incomplete_retry_count)
                    WHERE extra_jsonb #>> '{unlock,google,status}' = 'error'
                       OR extra_jsonb #>> '{unlock,chatgpt,status}' = 'error';
                ",
            )?;
            Ok(())
        })
    }

    fn backfill_definition_hashes(&self) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, subscription_id, name, proxy_type, server, port, config_json,
                        is_valid, local_port, error_count, last_error, last_validated,
                        created_at, updated_at, orphaned_at
                 FROM proxies
                 WHERE definition_hash IS NULL",
                &[],
            )?;
            if rows.is_empty() {
                return Ok(());
            }
            let proxies: Vec<_> = rows.iter().map(proxy_from_row).collect();
            let ids: Vec<_> = proxies.iter().map(|proxy| proxy.id.clone()).collect();
            let hashes: Vec<_> = proxies.iter().map(proxy_definition_hash).collect();
            conn.execute(
                "UPDATE proxies p
                 SET definition_hash = v.definition_hash
                 FROM UNNEST($1::text[], $2::bytea[]) AS v(id, definition_hash)
                 WHERE p.id = v.id",
                &[&ids, &hashes],
            )?;
            // PostgreSQL fires same-event triggers by name. During the
            // legacy hash backfill the health trigger sorts before the
            // definition/membership trigger, so it cannot see the newly
            // created definition yet. Fill only the still-missing canonical
            // health rows after all definition triggers have completed.
            conn.execute(
                "INSERT INTO proxy_health (
                    definition_id, health_state, consecutive_failures,
                    last_success_at, last_failure_at, next_check_at,
                    failure_kind, last_error, updated_at
                 )
                 SELECT DISTINCT ON (definition.id)
                        definition.id,
                        CASE
                            WHEN proxy.is_valid THEN 'healthy'
                            WHEN proxy.last_validated_ts IS NULL
                                 AND proxy.error_count = 0 THEN 'untested'
                            WHEN proxy.error_count >= 10 THEN 'unhealthy'
                            ELSE 'suspect'
                        END,
                        GREATEST(proxy.error_count, 0),
                        CASE WHEN proxy.is_valid THEN proxy.last_validated_ts END,
                        CASE WHEN NOT proxy.is_valid THEN proxy.last_validated_ts END,
                        CASE
                            WHEN proxy.last_validated_ts IS NULL THEN NOW()
                            WHEN proxy.is_valid
                                THEN proxy.last_validated_ts + INTERVAL '30 minutes'
                            WHEN proxy.error_count >= 10
                                THEN NOW() + INTERVAL '12 hours'
                            ELSE NOW() + INTERVAL '5 minutes'
                        END,
                        CASE WHEN proxy.is_valid
                             THEN NULL ELSE 'legacy_probe_failure' END,
                        proxy.last_error,
                        COALESCE(proxy.updated_at_ts, NOW())
                 FROM proxies proxy
                 JOIN proxy_definitions definition
                   ON definition.definition_hash = proxy.definition_hash
                 WHERE proxy.id = ANY($1::text[])
                 ORDER BY definition.id,
                          proxy.last_validated_ts DESC NULLS LAST,
                          proxy.updated_at_ts DESC NULLS LAST,
                          proxy.id
                 ON CONFLICT (definition_id) DO NOTHING",
                &[&ids],
            )?;
            tracing::info!("Backfilled definition hashes for {} proxies", ids.len());
            Ok(())
        })
    }

    fn backfill_normalized_exit_quality(&self) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.batch_execute(
                "INSERT INTO proxy_exit (definition_id, ip_address, observed_at)
                 SELECT DISTINCT ON (definition.id)
                        definition.id, zenproxy_try_inet(quality.ip_address),
                        COALESCE(quality.checked_at_ts, NOW())
                 FROM proxies proxy
                 JOIN proxy_definitions definition
                   ON definition.definition_hash = proxy.definition_hash
                 JOIN proxy_quality quality ON quality.proxy_id = proxy.id
                 WHERE zenproxy_try_inet(quality.ip_address) IS NOT NULL
                 ORDER BY definition.id, quality.checked_at_ts DESC NULLS LAST, proxy.id
                 ON CONFLICT (definition_id) DO NOTHING;

                 INSERT INTO exit_quality (
                    ip_address, country, ip_type, is_residential,
                    chatgpt_accessible, google_accessible, risk_score,
                    risk_level, unlock_json, extra_json, checked_at,
                    source_definition_id
                 )
                 SELECT DISTINCT ON (zenproxy_try_inet(quality.ip_address))
                        zenproxy_try_inet(quality.ip_address), quality.country,
                        quality.ip_type, quality.is_residential,
                        quality.chatgpt_accessible, quality.google_accessible,
                        quality.risk_score, quality.risk_level,
                        quality.extra_jsonb->'unlock', quality.extra_jsonb,
                        COALESCE(quality.checked_at_ts, NOW()), definition.id
                 FROM proxy_quality quality
                 JOIN proxies proxy ON proxy.id = quality.proxy_id
                 JOIN proxy_definitions definition
                   ON definition.definition_hash = proxy.definition_hash
                 WHERE zenproxy_try_inet(quality.ip_address) IS NOT NULL
                 ORDER BY zenproxy_try_inet(quality.ip_address),
                          quality.checked_at_ts DESC NULLS LAST, proxy.id
                 ON CONFLICT (ip_address) DO NOTHING;",
            )?;
            Ok(())
        })
    }

    fn finalize_normalization_cutover(&self) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.batch_execute(
                "DROP TRIGGER IF EXISTS trg_zenproxy_sync_normalized_proxy ON proxies;
                 DROP TRIGGER IF EXISTS trg_zenproxy_delete_normalized_membership ON proxies;
                 DROP TRIGGER IF EXISTS trg_zenproxy_sync_normalized_health ON proxies;
                 DROP TRIGGER IF EXISTS trg_zenproxy_sync_exit_quality ON proxy_quality;
                 DROP TRIGGER IF EXISTS trg_zenproxy_sync_normalized_runtime ON proxies;
                 DROP FUNCTION IF EXISTS zenproxy_sync_normalized_proxy();
                 DROP FUNCTION IF EXISTS zenproxy_delete_normalized_membership();
                 DROP FUNCTION IF EXISTS zenproxy_sync_normalized_health();
                 DROP FUNCTION IF EXISTS zenproxy_sync_exit_quality();
                 DROP FUNCTION IF EXISTS zenproxy_sync_normalized_runtime();",
            )?;
            Ok(())
        })
    }

    fn finalize_inventory_constraints(&self) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            let orphaned_quality = tx.execute(
                "DELETE FROM proxy_quality q
                 WHERE NOT EXISTS (SELECT 1 FROM proxies p WHERE p.id = q.proxy_id)",
                &[],
            )?;
            let orphaned_proxies = tx.execute(
                "DELETE FROM proxies p
                 WHERE NOT EXISTS (
                    SELECT 1 FROM subscriptions s WHERE s.id = p.subscription_id
                 )",
                &[],
            )?;
            tx.batch_execute(
                "DO $$
                 BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'fk_proxies_subscription'
                          AND conrelid = 'proxies'::regclass
                    ) THEN
                        ALTER TABLE proxies
                        ADD CONSTRAINT fk_proxies_subscription
                        FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
                        ON DELETE CASCADE NOT VALID;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'fk_proxy_quality_proxy'
                          AND conrelid = 'proxy_quality'::regclass
                    ) THEN
                        ALTER TABLE proxy_quality
                        ADD CONSTRAINT fk_proxy_quality_proxy
                        FOREIGN KEY (proxy_id) REFERENCES proxies(id)
                        ON DELETE CASCADE NOT VALID;
                    END IF;
                 END
                 $$;
                 ALTER TABLE proxies VALIDATE CONSTRAINT fk_proxies_subscription;
                 ALTER TABLE proxy_quality VALIDATE CONSTRAINT fk_proxy_quality_proxy;
                 ALTER TABLE proxies ALTER COLUMN definition_hash SET NOT NULL;",
            )?;
            tx.commit()?;
            if orphaned_quality > 0 || orphaned_proxies > 0 {
                tracing::warn!(
                    orphaned_quality,
                    orphaned_proxies,
                    "removed rows that violated newly enforced inventory foreign keys"
                );
            }
            Ok(())
        })
    }

    fn migrate_optional_search_indexes(&self) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.batch_execute(
                "CREATE EXTENSION IF NOT EXISTS pg_trgm;
                 CREATE INDEX IF NOT EXISTS idx_proxies_name_trgm
                    ON proxies USING gin (name gin_trgm_ops);
                 CREATE INDEX IF NOT EXISTS idx_proxies_server_trgm
                    ON proxies USING gin (server gin_trgm_ops);
                 CREATE INDEX IF NOT EXISTS idx_proxy_quality_ip_trgm
                    ON proxy_quality USING gin (ip_address gin_trgm_ops);
                 CREATE INDEX IF NOT EXISTS idx_subscription_proxies_name_trgm
                    ON subscription_proxies USING gin (display_name gin_trgm_ops);
                 CREATE INDEX IF NOT EXISTS idx_proxy_definitions_server_trgm
                    ON proxy_definitions USING gin (server gin_trgm_ops);
                 CREATE INDEX IF NOT EXISTS idx_proxy_exit_host_trgm
                    ON proxy_exit USING gin ((HOST(ip_address)) gin_trgm_ops);",
            )
        })
    }

    pub fn get_subscription_by_url(
        &self,
        url: &str,
    ) -> Result<Option<Subscription>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, name, sub_type, url, content, proxy_count,
                        raw_proxy_count, duplicate_proxy_count,
                        refresh_interval_mins, last_refresh_at, created_at, updated_at
                 FROM subscriptions
                 WHERE BTRIM(url) = $1
                 ORDER BY created_at ASC, id ASC
                 LIMIT 1",
                &[&url],
            )?;
            Ok(row.as_ref().map(subscription_from_row))
        })
    }

    /// Atomically create a URL subscription and its proxy inventory unless the
    /// same URL is already present. The advisory lock makes repeated clicks
    /// and concurrent requests idempotent without requiring legacy duplicate
    /// rows to be deleted before a unique index can be introduced.
    pub fn insert_subscription_with_proxies_unless_url_exists(
        &self,
        sub: &Subscription,
        proxies: &[ProxyRow],
    ) -> Result<Option<Subscription>, postgres::Error> {
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;

            if let Some(url) = sub.url.as_deref() {
                tx.query_one(
                    "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
                    &[&url],
                )?;
                if let Some(row) = tx.query_opt(
                    "SELECT id, name, sub_type, url, content, proxy_count,
                            raw_proxy_count, duplicate_proxy_count,
                            refresh_interval_mins, last_refresh_at, created_at, updated_at
                     FROM subscriptions
                     WHERE BTRIM(url) = $1
                     ORDER BY created_at ASC, id ASC
                     LIMIT 1",
                    &[&url],
                )? {
                    let existing = subscription_from_row(&row);
                    tx.commit()?;
                    return Ok(Some(existing));
                }
            }

            tx.execute(
                "INSERT INTO subscriptions (
                    id, name, sub_type, url, content, proxy_count,
                    raw_proxy_count, duplicate_proxy_count,
                    refresh_interval_mins, last_refresh_at, created_at, updated_at
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8,
                    $9, $10, $11, $12
                 )",
                &[
                    &sub.id,
                    &sub.name,
                    &sub.sub_type,
                    &sub.url,
                    &sub.content,
                    &sub.proxy_count,
                    &sub.raw_proxy_count,
                    &sub.duplicate_proxy_count,
                    &sub.refresh_interval_mins,
                    &sub.last_refresh_at,
                    &sub.created_at,
                    &sub.updated_at,
                ],
            )?;

            if !proxies.is_empty() {
                upsert_proxy_rows_tx(&mut tx, proxies)?;
            }

            tx.commit()?;
            Ok(None)
        })
    }

    pub fn get_subscriptions(&self) -> Result<Vec<Subscription>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, name, sub_type, url, content, proxy_count,
                        raw_proxy_count, duplicate_proxy_count,
                        refresh_interval_mins, last_refresh_at, created_at, updated_at
                 FROM subscriptions ORDER BY created_at DESC",
                &[],
            )?;
            Ok(rows.iter().map(subscription_from_row).collect())
        })
    }

    /// List metadata without returning potentially multi-megabyte inline
    /// subscription bodies. The edit dialog loads one body on demand.
    pub fn get_subscription_summaries(&self) -> Result<Vec<Subscription>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, name, sub_type, url, NULL::text AS content, proxy_count,
                        raw_proxy_count, duplicate_proxy_count,
                        refresh_interval_mins, last_refresh_at, created_at, updated_at
                 FROM subscriptions ORDER BY created_at DESC",
                &[],
            )?;
            Ok(rows.iter().map(subscription_from_row).collect())
        })
    }

    pub fn get_subscription(&self, id: &str) -> Result<Option<Subscription>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, name, sub_type, url, content, proxy_count,
                        raw_proxy_count, duplicate_proxy_count,
                        refresh_interval_mins, last_refresh_at, created_at, updated_at
                 FROM subscriptions WHERE id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(subscription_from_row))
        })
    }

    pub fn delete_subscription(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            let definition_ids: Vec<String> = tx
                .query(
                    "SELECT DISTINCT definition_id
                     FROM subscription_proxies WHERE subscription_id = $1",
                    &[&id],
                )?
                .iter()
                .map(|row| row.get(0))
                .collect();
            tx.execute("DELETE FROM subscriptions WHERE id = $1", &[&id])?;
            delete_unreferenced_definitions(&mut tx, &definition_ids)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn update_subscription_refresh_settings(
        &self,
        sub_id: &str,
        refresh_interval_mins: i32,
    ) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE subscriptions
                 SET refresh_interval_mins = $1, updated_at = $2
                 WHERE id = $3",
                &[&refresh_interval_mins, &now, &sub_id],
            )?;
            Ok(())
        })
    }

    pub fn update_subscription_settings(&self, sub: &Subscription) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE subscriptions
                 SET name = $1, sub_type = $2, url = $3, content = $4,
                     refresh_interval_mins = $5, updated_at = $6
                 WHERE id = $7",
                &[
                    &sub.name,
                    &sub.sub_type,
                    &sub.url,
                    &sub.content,
                    &sub.refresh_interval_mins,
                    &sub.updated_at,
                    &sub.id,
                ],
            )?;
            Ok(())
        })
    }

    /// Update a subscription after atomically reserving its new URL. Returns
    /// the conflicting subscription when another row already owns that URL.
    pub fn update_subscription_settings_unless_url_exists(
        &self,
        sub: &Subscription,
    ) -> Result<Option<Subscription>, postgres::Error> {
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            if let Some(url) = sub.url.as_deref() {
                tx.query_one(
                    "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
                    &[&url],
                )?;
                if let Some(row) = tx.query_opt(
                    "SELECT id, name, sub_type, url, content, proxy_count,
                            raw_proxy_count, duplicate_proxy_count,
                            refresh_interval_mins, last_refresh_at, created_at, updated_at
                     FROM subscriptions
                     WHERE BTRIM(url) = $1 AND id <> $2
                     ORDER BY created_at ASC, id ASC
                     LIMIT 1",
                    &[&url, &sub.id],
                )? {
                    let existing = subscription_from_row(&row);
                    tx.commit()?;
                    return Ok(Some(existing));
                }
            }

            tx.execute(
                "UPDATE subscriptions
                 SET name = $1, sub_type = $2, url = $3, content = $4,
                     refresh_interval_mins = $5, updated_at = $6
                 WHERE id = $7",
                &[
                    &sub.name,
                    &sub.sub_type,
                    &sub.url,
                    &sub.content,
                    &sub.refresh_interval_mins,
                    &sub.updated_at,
                    &sub.id,
                ],
            )?;
            tx.commit()?;
            Ok(None)
        })
    }

    pub fn get_subscription_default_refresh_interval_mins(
        &self,
        fallback: u64,
    ) -> Result<u64, postgres::Error> {
        self.with_conn(|conn| {
            let value: Option<String> = conn
                .query_opt(
                    "SELECT value FROM app_settings WHERE key = $1",
                    &[&SETTING_SUBSCRIPTION_DEFAULT_REFRESH_INTERVAL_MINS],
                )?
                .map(|row| row.get(0));

            Ok(value
                .as_deref()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(fallback))
        })
    }

    pub fn set_subscription_default_refresh_interval_mins(
        &self,
        refresh_interval_mins: u64,
    ) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let value = refresh_interval_mins.to_string();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO app_settings (key, value, updated_at)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (key) DO UPDATE SET
                    value = EXCLUDED.value,
                    updated_at = EXCLUDED.updated_at",
                &[
                    &SETTING_SUBSCRIPTION_DEFAULT_REFRESH_INTERVAL_MINS,
                    &value,
                    &now,
                ],
            )?;
            Ok(())
        })
    }

    pub fn mark_subscription_refreshed(
        &self,
        sub_id: &str,
        count: i32,
        raw_count: i32,
        duplicate_count: i32,
    ) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE subscriptions
                 SET proxy_count = $1, raw_proxy_count = $2,
                     duplicate_proxy_count = $3, last_refresh_at = $4, updated_at = $4
                 WHERE id = $5",
                &[&count, &raw_count, &duplicate_count, &now, &sub_id],
            )?;
            Ok(())
        })
    }

    pub fn insert_proxy(&self, proxy: &ProxyRow) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            upsert_proxy_rows_tx(&mut tx, std::slice::from_ref(proxy))?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn insert_proxies_batch(&self, proxies: &[ProxyRow]) -> Result<(), postgres::Error> {
        if proxies.is_empty() {
            return Ok(());
        }

        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            upsert_proxy_rows_tx(&mut tx, proxies)?;

            tx.commit()?;
            Ok(())
        })
    }

    pub fn get_all_proxies(&self) -> Result<Vec<ProxyRow>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, subscription_id, name, proxy_type, server, port, config_json,
                        is_valid, local_port, error_count, last_error, last_validated,
                        created_at, updated_at, orphaned_at
                 FROM normalized_proxies ORDER BY created_at_ts DESC",
                &[],
            )?;
            Ok(rows.iter().map(proxy_from_row).collect())
        })
    }

    /// Per-source duplicate data and pairwise source overlap. Only current
    /// inventory participates; orphaned fallback rows intentionally do not.
    pub fn get_subscription_duplicate_overview(
        &self,
    ) -> Result<(Vec<SubscriptionDuplicateStats>, Vec<SubscriptionOverlap>), postgres::Error> {
        self.with_conn(|conn| {
            let stat_rows = conn.query(
                "SELECT
                    s.id AS subscription_id,
                    COUNT(p.id) AS stored_nodes,
                    COUNT(p.id) FILTER (WHERE p.is_valid = TRUE) AS valid_nodes,
                    COUNT(DISTINCT (LOWER(p.server), p.port, p.proxy_type)) AS unique_endpoints,
                    GREATEST(
                        COUNT(p.id) - COUNT(DISTINCT (LOWER(p.server), p.port, p.proxy_type)),
                        0
                    ) AS duplicate_endpoint_nodes,
                    COUNT(q.ip_address) FILTER (
                        WHERE q.ip_address IS NOT NULL AND BTRIM(q.ip_address) <> ''
                    ) AS measured_exit_nodes,
                    COUNT(DISTINCT q.ip_address) FILTER (
                        WHERE q.ip_address IS NOT NULL AND BTRIM(q.ip_address) <> ''
                    ) AS unique_exit_ips
                 FROM subscriptions s
                 LEFT JOIN normalized_proxies p
                   ON p.subscription_id = s.id AND p.orphaned_at IS NULL
                 LEFT JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                 GROUP BY s.id",
                &[],
            )?;
            let stats = stat_rows
                .iter()
                .map(|row| {
                    let measured_exit_nodes: i64 = row.get("measured_exit_nodes");
                    let unique_exit_ips: i64 = row.get("unique_exit_ips");
                    SubscriptionDuplicateStats {
                        subscription_id: row.get("subscription_id"),
                        stored_nodes: row.get("stored_nodes"),
                        valid_nodes: row.get("valid_nodes"),
                        unique_endpoints: row.get("unique_endpoints"),
                        duplicate_endpoint_nodes: row.get("duplicate_endpoint_nodes"),
                        measured_exit_nodes,
                        unique_exit_ips,
                        duplicate_exit_ip_nodes: (measured_exit_nodes - unique_exit_ips).max(0),
                    }
                })
                .collect();

            let overlap_rows = conn.query(
                "WITH endpoint_sources AS (
                    SELECT DISTINCT subscription_id, LOWER(server) AS server, port, proxy_type
                    FROM normalized_proxies
                    WHERE orphaned_at IS NULL
                 ), endpoint_overlap AS (
                    SELECT a.subscription_id AS left_id, b.subscription_id AS right_id,
                           COUNT(*) AS shared_endpoints
                    FROM endpoint_sources a
                    JOIN endpoint_sources b
                      ON a.server = b.server AND a.port = b.port
                     AND a.proxy_type = b.proxy_type
                     AND a.subscription_id < b.subscription_id
                     GROUP BY a.subscription_id, b.subscription_id
                 ), exact_sources AS (
                    SELECT DISTINCT subscription_id, definition_hash
                    FROM normalized_proxies
                    WHERE orphaned_at IS NULL AND definition_hash IS NOT NULL
                 ), exact_overlap AS (
                    SELECT a.subscription_id AS left_id, b.subscription_id AS right_id,
                           COUNT(*) AS shared_exact_nodes
                    FROM exact_sources a
                    JOIN exact_sources b
                      ON a.definition_hash = b.definition_hash
                     AND a.subscription_id < b.subscription_id
                    GROUP BY a.subscription_id, b.subscription_id
                 ), exit_sources AS (
                    SELECT DISTINCT p.subscription_id, q.ip_address
                    FROM normalized_proxies p
                    JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                    WHERE p.orphaned_at IS NULL
                      AND q.ip_address IS NOT NULL AND BTRIM(q.ip_address) <> ''
                 ), exit_overlap AS (
                    SELECT a.subscription_id AS left_id, b.subscription_id AS right_id,
                           COUNT(*) AS shared_exit_ips
                    FROM exit_sources a
                    JOIN exit_sources b
                      ON a.ip_address = b.ip_address
                     AND a.subscription_id < b.subscription_id
                     GROUP BY a.subscription_id, b.subscription_id
                 ), overlap_pairs AS (
                    SELECT left_id, right_id FROM endpoint_overlap
                    UNION
                    SELECT left_id, right_id FROM exact_overlap
                    UNION
                    SELECT left_id, right_id FROM exit_overlap
                 )
                 SELECT pairs.left_id, pairs.right_id,
                        COALESCE(d.shared_exact_nodes, 0) AS shared_exact_nodes,
                        COALESCE(e.shared_endpoints, 0) AS shared_endpoints,
                        COALESCE(x.shared_exit_ips, 0) AS shared_exit_ips
                 FROM overlap_pairs pairs
                 LEFT JOIN exact_overlap d USING (left_id, right_id)
                 LEFT JOIN endpoint_overlap e USING (left_id, right_id)
                 LEFT JOIN exit_overlap x USING (left_id, right_id)
                 ORDER BY (
                    COALESCE(d.shared_exact_nodes, 0)
                    + COALESCE(e.shared_endpoints, 0)
                    + COALESCE(x.shared_exit_ips, 0)
                 ) DESC, pairs.left_id, pairs.right_id",
                &[],
            )?;
            let mut overlaps = overlap_rows
                .iter()
                .map(|row| {
                    SubscriptionOverlap {
                        left_subscription_id: row.get("left_id"),
                        right_subscription_id: row.get("right_id"),
                        shared_exact_nodes: row.get("shared_exact_nodes"),
                        shared_endpoints: row.get("shared_endpoints"),
                        shared_exit_ips: row.get("shared_exit_ips"),
                    }
                })
                .collect::<Vec<_>>();
            overlaps.sort_by(|left, right| {
                (right.shared_exact_nodes + right.shared_endpoints + right.shared_exit_ips)
                    .cmp(&(left.shared_exact_nodes + left.shared_endpoints + left.shared_exit_ips))
                    .then_with(|| left.left_subscription_id.cmp(&right.left_subscription_id))
                    .then_with(|| left.right_subscription_id.cmp(&right.right_subscription_id))
            });

            Ok((stats, overlaps))
        })
    }

    pub fn get_valid_export_proxies(
        &self,
        proxy_type: Option<&str>,
    ) -> Result<Vec<ProxyRow>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = if let Some(proxy_type) = proxy_type {
                conn.query(
                    "SELECT id, subscription_id, name, proxy_type, server, port, config_json,
                            is_valid, local_port, error_count, last_error, last_validated,
                            created_at, updated_at, orphaned_at
                     FROM (
                        SELECT DISTINCT ON (q.ip_address)
                            p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port,
                            p.config_json, p.is_valid, p.local_port, p.error_count, p.last_error,
                            p.last_validated, p.created_at, p.updated_at, p.orphaned_at
                        FROM normalized_proxies p
                        JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                        WHERE p.is_valid = TRUE
                          AND p.orphaned_at IS NULL
                          AND p.proxy_type = $1
                          AND q.ip_address IS NOT NULL
                          AND BTRIM(q.ip_address) <> ''
                        ORDER BY q.ip_address, p.error_count ASC,
                                 p.last_validated DESC NULLS LAST, p.updated_at DESC, p.id ASC
                     ) deduplicated
                     ORDER BY error_count ASC, last_validated DESC NULLS LAST,
                              updated_at DESC, name ASC",
                    &[&proxy_type],
                )?
            } else {
                conn.query(
                    "SELECT id, subscription_id, name, proxy_type, server, port, config_json,
                            is_valid, local_port, error_count, last_error, last_validated,
                            created_at, updated_at, orphaned_at
                     FROM (
                        SELECT DISTINCT ON (q.ip_address)
                            p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port,
                            p.config_json, p.is_valid, p.local_port, p.error_count, p.last_error,
                            p.last_validated, p.created_at, p.updated_at, p.orphaned_at
                        FROM normalized_proxies p
                        JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                        WHERE p.is_valid = TRUE
                          AND p.orphaned_at IS NULL
                          AND q.ip_address IS NOT NULL
                          AND BTRIM(q.ip_address) <> ''
                        ORDER BY q.ip_address, p.error_count ASC,
                                 p.last_validated DESC NULLS LAST, p.updated_at DESC, p.id ASC
                     ) deduplicated
                     ORDER BY proxy_type ASC, error_count ASC,
                              last_validated DESC NULLS LAST, updated_at DESC, name ASC",
                    &[],
                )?
            };
            Ok(rows.iter().map(proxy_from_row).collect())
        })
    }

    pub fn get_proxy_record(
        &self,
        id: &str,
    ) -> Result<Option<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT
                    p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port, p.config_json,
                    p.is_valid, p.local_port, p.error_count, p.last_error, p.last_validated,
                    p.created_at, p.updated_at, p.orphaned_at,
                    q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                    q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                    q.extra_json, q.checked_at
                 FROM normalized_proxies p
                 LEFT JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                 WHERE p.id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(proxy_record_from_join_row))
        })
    }

    /// Fetch a caller-ordered set of memberships in one round trip. Missing
    /// ids are omitted, matching repeated `get_proxy_record` semantics.
    pub fn get_proxy_records(
        &self,
        ids: &[String],
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        self.with_conn(|conn| {
            let rows = conn.query(
                "WITH requested AS (
                    SELECT id, ordinal
                    FROM UNNEST($1::text[]) WITH ORDINALITY AS value(id, ordinal)
                 )
                 SELECT
                    p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port,
                    p.config_json, p.is_valid, p.local_port, p.error_count,
                    p.last_error, p.last_validated, p.created_at, p.updated_at,
                    p.orphaned_at, q.proxy_id, q.ip_address, q.country, q.ip_type,
                    q.is_residential, q.chatgpt_accessible, q.google_accessible,
                    q.risk_score, q.risk_level, q.extra_json, q.checked_at
                 FROM requested
                 JOIN normalized_proxies p ON p.id = requested.id
                 LEFT JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                 ORDER BY requested.ordinal",
                &[&ids],
            )?;
            Ok(rows.iter().map(proxy_record_from_join_row).collect())
        })
    }

    pub fn get_hot_proxy_records(
        &self,
        limit: usize,
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        let limit = limit as i64;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT
                    id, subscription_id, name, proxy_type, server, port, config_json,
                    is_valid, local_port, error_count, last_error, last_validated,
                    created_at, updated_at, orphaned_at,
                    proxy_id, ip_address, country, ip_type, is_residential,
                    chatgpt_accessible, google_accessible, risk_score, risk_level,
                    extra_json, checked_at
                 FROM (
                    SELECT DISTINCT ON (q.ip_address)
                        p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port,
                        p.config_json, p.is_valid, p.local_port, p.error_count, p.last_error,
                        p.last_validated, p.created_at, p.updated_at, p.orphaned_at,
                        q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                        q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                        q.extra_json, q.checked_at
                    FROM normalized_proxies p
                    JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                    WHERE p.is_valid = TRUE
                      AND p.orphaned_at IS NULL
                      AND q.ip_address IS NOT NULL
                      AND BTRIM(q.ip_address) <> ''
                    ORDER BY q.ip_address, p.error_count ASC,
                             p.last_validated DESC NULLS LAST, p.updated_at DESC, p.id ASC
                 ) deduplicated
                 ORDER BY error_count ASC, last_validated DESC NULLS LAST, updated_at DESC
                 LIMIT $1",
                &[&limit],
            )?;
            Ok(rows.iter().map(proxy_record_from_join_row).collect())
        })
    }

    /// Load the complete selectable inventory for the in-memory data-plane
    /// index. Unlike the hot binding set this deliberately keeps alternative
    /// definitions that share an exit IP, allowing immediate failover within
    /// an exit group without returning to the database.
    pub fn get_selectable_proxy_records(
        &self,
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT
                    id, subscription_id, name, proxy_type, server, port, config_json,
                    is_valid, local_port, error_count, last_error, last_validated,
                    created_at, updated_at, orphaned_at,
                    proxy_id, ip_address, country, ip_type, is_residential,
                    chatgpt_accessible, google_accessible, risk_score, risk_level,
                    extra_json, checked_at
                 FROM (
                    SELECT DISTINCT ON (p.definition_id)
                        p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port,
                        p.config_json, p.is_valid, p.local_port, p.error_count,
                        p.last_error, p.last_validated, p.created_at, p.updated_at,
                        p.orphaned_at, p.last_validated_ts, p.updated_at_ts,
                        q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                        q.chatgpt_accessible, q.google_accessible, q.risk_score,
                        q.risk_level, q.extra_json, q.checked_at
                    FROM normalized_proxies p
                    JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                    WHERE p.is_valid = TRUE
                      AND p.orphaned_at IS NULL
                      AND q.ip_address IS NOT NULL
                      AND BTRIM(q.ip_address) <> ''
                    ORDER BY p.definition_id, p.updated_at_ts DESC, p.id ASC
                 ) definitions
                 ORDER BY ip_address, error_count ASC,
                          last_validated_ts DESC NULLS LAST, updated_at_ts DESC, id ASC",
                &[],
            )?;
            Ok(rows.iter().map(proxy_record_from_join_row).collect())
        })
    }

    pub fn claim_due_quality_proxy_records(
        &self,
        limit: usize,
        stale_before: &str,
        max_incomplete_retries: u8,
        quality_schema_version: u8,
        lease_owner: &str,
        lease_seconds: u64,
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        let limit = limit.max(1) as i64;
        let max_incomplete_retries = max_incomplete_retries as i32;
        let quality_schema_version = quality_schema_version as i32;
        let lease_seconds = lease_seconds.max(60).min(i64::MAX as u64) as i64;
        self.with_conn(|conn| {
            let rows = conn.query(
                "WITH candidates AS (
                    SELECT
                        COALESCE(
                            observed.ip_address::text,
                            NULLIF(BTRIM(q.ip_address), ''),
                            ENCODE(p.definition_hash, 'hex')
                        ) AS quality_group,
                        p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port,
                        p.config_json, p.is_valid, p.local_port, p.error_count, p.last_error,
                        p.last_validated, p.created_at, p.updated_at, p.orphaned_at,
                        p.last_validated_ts, p.updated_at_ts,
                        q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                        q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                        q.extra_json, q.checked_at, q.checked_at_ts
                    FROM normalized_proxies p
                    LEFT JOIN proxy_exit observed
                      ON observed.definition_id = p.definition_id
                    LEFT JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                    WHERE p.is_valid = TRUE
                      AND p.orphaned_at IS NULL
                      AND (
                           q.proxy_id IS NULL
                           OR q.checked_at_ts <= zenproxy_try_timestamptz($1::text)
                           OR q.schema_version < $3
                           OR (
                               (
                                   q.country IS NULL OR q.ip_type IS NULL OR q.ip_address IS NULL
                                   OR q.risk_level = 'Unknown'
                                   OR COALESCE(q.extra_jsonb #>> '{unlock,google,status}', '') = 'error'
                                   OR COALESCE(q.extra_jsonb #>> '{unlock,chatgpt,status}', '') = 'error'
                               )
                               AND q.incomplete_retry_count < $2
                               AND COALESCE(
                                   zenproxy_try_timestamptz(q.extra_jsonb ->> 'next_retry_at'),
                                   '-infinity'::timestamptz
                               ) <= NOW()
                           )
                      )
                 ), representatives AS (
                    SELECT DISTINCT ON (quality_group) *
                    FROM candidates
                    WHERE NOT EXISTS (
                        SELECT 1 FROM quality_check_leases active_lease
                        WHERE active_lease.quality_key = candidates.quality_group
                          AND active_lease.lease_until > NOW()
                    )
                    ORDER BY quality_group,
                             CASE WHEN local_port IS NULL THEN 1 ELSE 0 END,
                             checked_at_ts ASC NULLS FIRST,
                             last_validated_ts DESC NULLS LAST,
                             updated_at_ts DESC NULLS LAST,
                             id
                    LIMIT $4
                 ), claimed AS (
                    INSERT INTO quality_check_leases AS leases (
                        quality_key, lease_owner, lease_until
                    )
                    SELECT quality_group, $5,
                           NOW() + ($6::bigint * INTERVAL '1 second')
                    FROM representatives
                    ON CONFLICT (quality_key) DO UPDATE SET
                        lease_owner = EXCLUDED.lease_owner,
                        lease_until = EXCLUDED.lease_until
                    WHERE leases.lease_until <= NOW()
                       OR leases.lease_owner = EXCLUDED.lease_owner
                    RETURNING quality_key
                 )
                 SELECT id, subscription_id, name, proxy_type, server, port,
                        config_json, is_valid, local_port, error_count, last_error,
                        last_validated, created_at, updated_at, orphaned_at,
                        proxy_id, ip_address, country, ip_type, is_residential,
                        chatgpt_accessible, google_accessible, risk_score, risk_level,
                        extra_json, checked_at
                 FROM representatives
                 JOIN claimed ON claimed.quality_key = representatives.quality_group
                 ORDER BY checked_at_ts ASC NULLS FIRST,
                          last_validated_ts DESC NULLS LAST,
                          updated_at_ts DESC NULLS LAST
                 LIMIT $4",
                &[
                    &stale_before,
                    &max_incomplete_retries,
                    &quality_schema_version,
                    &limit,
                    &lease_owner,
                    &lease_seconds,
                ],
            )?;
            Ok(rows.iter().map(proxy_record_from_join_row).collect())
        })
    }

    pub fn release_quality_leases(&self, lease_owner: &str) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            Ok(conn.execute(
                "DELETE FROM quality_check_leases WHERE lease_owner = $1",
                &[&lease_owner],
            )? as usize)
        })
    }

    /// Atomically claim one representative per stable proxy definition. The
    /// lease is written in the same statement that uses SKIP LOCKED, so the
    /// row cannot become visible to another process when a SELECT transaction
    /// ends before the network probe starts.
    pub fn claim_due_validation_proxy_records(
        &self,
        limit: usize,
        lease_owner: &str,
        lease_seconds: u64,
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        let limit = limit.max(1) as i64;
        let lease_seconds = lease_seconds.max(30).min(i64::MAX as u64) as i64;
        self.with_conn(|conn| {
            let rows = conn.query(
                "WITH candidates AS (
                    SELECT h.definition_id
                    FROM proxy_health h
                    WHERE h.next_check_at <= NOW()
                      AND (h.lease_until IS NULL OR h.lease_until <= NOW())
                      AND EXISTS (
                        SELECT 1 FROM subscription_proxies membership
                        WHERE membership.definition_id = h.definition_id
                          AND membership.orphaned_at IS NULL
                      )
                    ORDER BY
                        CASE h.health_state
                            WHEN 'untested' THEN 0
                            WHEN 'suspect' THEN 1
                            WHEN 'unhealthy' THEN 2
                            ELSE 3
                        END,
                        h.next_check_at ASC,
                        h.definition_id ASC
                    LIMIT $1
                    FOR UPDATE SKIP LOCKED
                 ), claimed AS (
                    UPDATE proxy_health h
                    SET lease_owner = $2,
                        lease_until = NOW() + ($3::bigint * INTERVAL '1 second'),
                        updated_at = NOW()
                    FROM candidates c
                    WHERE h.definition_id = c.definition_id
                    RETURNING h.definition_id
                 ), representatives AS (
                    SELECT DISTINCT ON (membership.definition_id)
                        membership.definition_id,
                        p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port,
                        p.config_json, p.is_valid, p.local_port, p.error_count, p.last_error,
                        p.last_validated, p.created_at, p.updated_at, p.orphaned_at,
                        q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                        q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                        q.extra_json, q.checked_at
                    FROM claimed
                    JOIN subscription_proxies membership
                      ON membership.definition_id = claimed.definition_id
                     AND membership.orphaned_at IS NULL
                    JOIN normalized_proxies p ON p.id = membership.source_proxy_id
                    LEFT JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                    ORDER BY membership.definition_id,
                             CASE WHEN p.local_port IS NULL THEN 1 ELSE 0 END,
                             p.error_count ASC,
                             p.last_validated_ts DESC NULLS LAST,
                             p.updated_at_ts DESC NULLS LAST,
                             p.id ASC
                 )
                 SELECT id, subscription_id, name, proxy_type, server, port,
                        config_json, is_valid, local_port, error_count, last_error,
                        last_validated, created_at, updated_at, orphaned_at,
                        proxy_id, ip_address, country, ip_type, is_residential,
                        chatgpt_accessible, google_accessible, risk_score, risk_level,
                        extra_json, checked_at
                 FROM representatives",
                &[&limit, &lease_owner, &lease_seconds],
            )?;
            Ok(rows.iter().map(proxy_record_from_join_row).collect())
        })
    }

    pub fn release_validation_leases(
        &self,
        lease_owner: &str,
        source_ids: &[String],
        retry_after_seconds: u64,
    ) -> Result<usize, postgres::Error> {
        if source_ids.is_empty() {
            return Ok(0);
        }
        let retry_after_seconds = retry_after_seconds.min(i64::MAX as u64) as i64;
        self.with_conn(|conn| {
            let updated = conn.execute(
                "UPDATE proxy_health health
                 SET lease_owner = NULL,
                     lease_until = NULL,
                     next_check_at = LEAST(
                        health.next_check_at,
                        NOW() + ($3::bigint * INTERVAL '1 second')
                     ),
                     updated_at = NOW()
                 FROM subscription_proxies membership
                 WHERE membership.definition_id = health.definition_id
                   AND membership.source_proxy_id = ANY($2::text[])
                   AND health.lease_owner = $1",
                &[&lease_owner, &source_ids, &retry_after_seconds],
            )?;
            Ok(updated as usize)
        })
    }

    pub fn delete_orphaned_non_valid_before(&self, cutoff: &str) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            let rows = tx.query(
                "DELETE FROM subscription_proxies membership
                 USING proxy_health health
                 WHERE health.definition_id = membership.definition_id
                   AND health.health_state <> 'healthy'
                   AND membership.orphaned_at IS NOT NULL
                   AND membership.orphaned_at <= zenproxy_try_timestamptz($1)
                 RETURNING membership.definition_id",
                &[&cutoff],
            )?;
            let definition_ids: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
            delete_unreferenced_definitions(&mut tx, &definition_ids)?;
            tx.commit()?;
            Ok(rows.len())
        })
    }

    pub fn count_all_proxies(&self) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            let count: i64 = conn
                .query_one("SELECT COUNT(*) FROM normalized_proxies", &[])?
                .get(0);
            Ok(count as usize)
        })
    }

    pub fn count_valid_proxies(&self) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            let count: i64 = conn
                .query_one(
                    "SELECT COUNT(*) FROM normalized_proxies WHERE is_valid = TRUE",
                    &[],
                )?
                .get(0);
            Ok(count as usize)
        })
    }

    pub fn count_untested_proxies(&self) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            let count: i64 = conn
                .query_one(
                    "SELECT COUNT(*) FROM normalized_proxies
                     WHERE is_valid = FALSE
                       AND last_validated IS NULL
                       AND orphaned_at IS NULL",
                    &[],
                )?
                .get(0);
            Ok(count as usize)
        })
    }

    pub fn list_proxy_page(
        &self,
        query: &ProxyListQuery,
    ) -> Result<ProxyListPage, postgres::Error> {
        let page_size = query.page_size.clamp(1, 200);
        let requested_page = query.page.max(1);

        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();
        let where_clause = build_proxy_list_where(query, &mut params);
        let sort_expr = proxy_list_sort_expr(query.sort.as_deref());
        let dir = if matches!(query.dir.as_deref(), Some("desc")) {
            "DESC"
        } else {
            "ASC"
        };
        let sort_key = proxy_list_sort_key(query.sort.as_deref());
        let cursor = query
            .cursor
            .as_deref()
            .and_then(decode_proxy_list_cursor)
            .filter(|cursor| {
                cursor.sort == sort_key
                    && cursor.dir.eq_ignore_ascii_case(dir)
                    && proxy_cursor_value_is_valid(cursor, sort_key)
            });
        let backwards = cursor.is_some()
            && matches!(query.direction.as_deref(), Some("prev") | Some("previous"));

        let count_params = params;
        self.with_conn(|conn| {
            // Cursor requests already have their totals from the first page. Avoid
            // repeating a million-row COUNT on every next/previous click.
            let counts_available = cursor.is_none();
            let (filtered, total) = if counts_available {
                let count_refs: Vec<&(dyn ToSql + Sync)> = count_params
                    .iter()
                    .map(|p| &**p as &(dyn ToSql + Sync))
                    .collect();
                let sql = format!(
                    "SELECT
                        COUNT(*) AS filtered,
                    (SELECT COUNT(*) FROM normalized_proxies WHERE orphaned_at IS NULL) AS total
                     FROM normalized_proxies p
                     LEFT JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                     {where_clause}"
                );
                let row = conn.query_one(&sql, &count_refs)?;
                let filtered: i64 = row.get("filtered");
                let total: i64 = row.get("total");
                (filtered as usize, total as usize)
            } else {
                (0, 0)
            };

        // The admin/user list represents the current subscription contents.
        // Orphaned rows are retained internally for smooth refresh/rechecking,
        // but are not eligible for export and must not inflate the UI totals.
        let total_pages = if filtered == 0 {
            0
        } else {
            filtered.div_ceil(page_size)
        };
        // A filter change or deletion can make the requested page disappear.
        // Return the last available page instead of a misleading empty result.
        let page = requested_page.min(total_pages.max(1));
        let offset = (page - 1).saturating_mul(page_size).min(i64::MAX as usize) as i64;

        let mut select_params = count_params;
        let cursor_clause = cursor
            .as_ref()
            .map(|cursor| {
                build_proxy_cursor_clause(
                    cursor,
                    sort_expr,
                    sort_key,
                    dir,
                    backwards,
                    &mut select_params,
                )
            })
            .unwrap_or_default();
        // Ask for one extra row so has_next/has_previous does not need another query.
        select_params.push(Box::new((page_size + 1) as i64));
        let limit_idx = select_params.len();
        let query_dir = if backwards {
            if dir == "ASC" {
                "DESC"
            } else {
                "ASC"
            }
        } else {
            dir
        };
        let id_dir = if (dir == "ASC") ^ backwards {
            "ASC"
        } else {
            "DESC"
        };
        // OFFSET remains only for legacy callers that do not send a cursor.
        let legacy_offset = if cursor.is_none() { offset } else { 0 };
        select_params.push(Box::new(legacy_offset));
        let offset_idx = select_params.len();

            let param_refs: Vec<&(dyn ToSql + Sync)> = select_params
                .iter()
                .map(|p| &**p as &(dyn ToSql + Sync))
                .collect();
            let sql = format!(
                "SELECT
                    p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port, p.local_port,
                    p.error_count, p.is_valid, p.last_validated,
                    q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                    q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                    q.extra_json, q.checked_at,
                    ({sort_expr})::text AS cursor_value
                 FROM normalized_proxies p
                 LEFT JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                 {where_clause} {cursor_clause}
                 ORDER BY {sort_expr} {query_dir}, p.id {id_dir}
                 LIMIT ${limit_idx} OFFSET ${offset_idx}"
            );
            let rows = conn.query(&sql, &param_refs)?;
            let has_extra = rows.len() > page_size;
            let visible_rows = &rows[..rows.len().min(page_size)];
            let mut proxies: Vec<_> = visible_rows.iter().map(proxy_list_item_from_row).collect();
            let mut cursor_rows: Vec<_> = visible_rows.iter().collect();
            if backwards {
                proxies.reverse();
                cursor_rows.reverse();
            }
            let cursor_for = |row: &&Row| {
                encode_proxy_list_cursor(&ProxyListCursor {
                    sort: sort_key.to_string(),
                    dir: dir.to_string(),
                    value: row.get("cursor_value"),
                    id: row.get("id"),
                })
            };
            let next_cursor = cursor_rows.last().and_then(cursor_for);
            let prev_cursor = cursor_rows.first().and_then(cursor_for);
            let has_next = if backwards {
                cursor.is_some()
            } else {
                has_extra
            };
            let has_previous = if backwards {
                has_extra
            } else {
                cursor.is_some()
            };
            Ok(ProxyListPage {
                proxies,
                total,
                filtered,
                page,
                page_size,
                total_pages,
                next_cursor,
                prev_cursor,
                has_next,
                has_previous,
                counts_available,
            })
        })
    }

    pub fn get_proxies_by_subscription(
        &self,
        sub_id: &str,
    ) -> Result<Vec<ProxyRow>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, subscription_id, name, proxy_type, server, port, config_json,
                        is_valid, local_port, error_count, last_error, last_validated,
                        created_at, updated_at, orphaned_at
                 FROM normalized_proxies WHERE subscription_id = $1 ORDER BY name",
                &[&sub_id],
            )?;
            Ok(rows.iter().map(proxy_from_row).collect())
        })
    }

    pub fn delete_proxy(&self, id: &str) -> Result<(), postgres::Error> {
        self.delete_proxies(&[id.to_string()])
    }

    pub fn delete_proxies(&self, ids: &[String]) -> Result<(), postgres::Error> {
        if ids.is_empty() {
            return Ok(());
        }
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            let definition_ids: Vec<String> = tx
                .query(
                    "DELETE FROM subscription_proxies
                     WHERE source_proxy_id = ANY($1::text[])
                     RETURNING definition_id",
                    &[&ids],
                )?
                .iter()
                .map(|row| row.get(0))
                .collect();
            delete_unreferenced_definitions(&mut tx, &definition_ids)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn delete_proxies_by_subscription(&self, sub_id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            let definition_ids: Vec<String> = tx
                .query(
                    "DELETE FROM subscription_proxies
                     WHERE subscription_id = $1 RETURNING definition_id",
                    &[&sub_id],
                )?
                .iter()
                .map(|row| row.get(0))
                .collect();
            delete_unreferenced_definitions(&mut tx, &definition_ids)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn update_proxy_validation(
        &self,
        id: &str,
        is_valid: bool,
        error: Option<&str>,
    ) -> Result<(), postgres::Error> {
        self.apply_validation_outcomes(
            &[ProxyValidationOutcome {
                source_id: id.to_string(),
                is_valid,
                error: error.map(str::to_string),
                exit_ip: None,
                failure_kind: (!is_valid).then(|| "probe_failure".to_string()),
            }],
            10,
        )?;
        Ok(())
    }

    /// Persist an entire validation wave with one health update per canonical
    /// definition. Membership ids are expanded only in the returned result so
    /// callers can refresh their in-memory views without duplicating DB state.
    pub fn apply_validation_outcomes(
        &self,
        outcomes: &[ProxyValidationOutcome],
        unhealthy_threshold: u32,
    ) -> Result<Vec<AppliedProxyValidation>, postgres::Error> {
        if outcomes.is_empty() {
            return Ok(Vec::new());
        }
        let source_ids: Vec<_> = outcomes
            .iter()
            .map(|outcome| outcome.source_id.clone())
            .collect();
        let valid: Vec<_> = outcomes.iter().map(|outcome| outcome.is_valid).collect();
        let errors: Vec<_> = outcomes
            .iter()
            .map(|outcome| outcome.error.clone())
            .collect();
        let exit_ips: Vec<_> = outcomes
            .iter()
            .map(|outcome| outcome.exit_ip.clone())
            .collect();
        let failure_kinds: Vec<_> = outcomes
            .iter()
            .map(|outcome| outcome.failure_kind.clone())
            .collect();
        let unhealthy_threshold = unhealthy_threshold.max(1).min(i32::MAX as u32) as i32;
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            let rows = tx.query(
                "WITH input AS (
                    SELECT *
                    FROM UNNEST(
                        $1::text[], $2::bool[], $3::text[], $4::text[], $5::text[]
                    )
                         WITH ORDINALITY
                         AS v(source_id, is_valid, error_text, exit_ip, failure_kind, ordinal)
                 ), resolved AS (
                    SELECT DISTINCT ON (membership.definition_id)
                           membership.definition_id, input.is_valid,
                           input.error_text, input.exit_ip, input.failure_kind
                    FROM input
                    JOIN subscription_proxies membership
                      ON membership.source_proxy_id = input.source_id
                    ORDER BY membership.definition_id, input.ordinal DESC
                 ), updated AS (
                    UPDATE proxy_health health
                    SET health_state = CASE
                            WHEN resolved.is_valid THEN 'healthy'
                            WHEN health.consecutive_failures + 1 >= $6 THEN 'unhealthy'
                            ELSE 'suspect'
                        END,
                        consecutive_failures = CASE
                            WHEN resolved.is_valid THEN 0
                            ELSE health.consecutive_failures + 1
                        END,
                        last_success_at = CASE
                            WHEN resolved.is_valid THEN NOW()
                            ELSE health.last_success_at
                        END,
                        last_failure_at = CASE
                            WHEN resolved.is_valid THEN health.last_failure_at
                            ELSE NOW()
                        END,
                        next_check_at = CASE
                            WHEN resolved.is_valid THEN NOW() + INTERVAL '30 minutes'
                                + (RANDOM() * INTERVAL '5 minutes')
                            WHEN health.consecutive_failures + 1 >= $6
                                THEN NOW() + INTERVAL '12 hours'
                                     + (RANDOM() * INTERVAL '30 minutes')
                            ELSE NOW() + CASE
                                WHEN health.consecutive_failures + 1 <= 1
                                    THEN INTERVAL '5 minutes'
                                WHEN health.consecutive_failures + 1 = 2
                                    THEN INTERVAL '15 minutes'
                                WHEN health.consecutive_failures + 1 = 3
                                    THEN INTERVAL '60 minutes'
                                ELSE INTERVAL '180 minutes'
                            END
                        END,
                        failure_kind = CASE
                            WHEN resolved.is_valid THEN resolved.failure_kind
                            ELSE COALESCE(resolved.failure_kind, 'probe_failure')
                        END,
                        last_error = resolved.error_text,
                        lease_owner = NULL,
                        lease_until = NULL,
                        updated_at = NOW()
                    FROM resolved
                    WHERE health.definition_id = resolved.definition_id
                    RETURNING health.definition_id, resolved.is_valid, resolved.exit_ip
                 )
                 SELECT membership.source_proxy_id, updated.is_valid, updated.exit_ip
                 FROM updated
                 JOIN subscription_proxies membership
                   ON membership.definition_id = updated.definition_id",
                &[
                    &source_ids,
                    &valid,
                    &errors,
                    &exit_ips,
                    &failure_kinds,
                    &unhealthy_threshold,
                ],
            )?;
            let mut applied: Vec<_> = rows
                .iter()
                .map(|row| AppliedProxyValidation {
                    proxy_id: row.get(0),
                    is_valid: row.get(1),
                    exit_ip: row.get(2),
                    deleted_orphan: false,
                })
                .collect();

            tx.execute(
                "WITH input AS (
                    SELECT *
                    FROM UNNEST($1::text[], $2::bool[], $3::text[])
                         WITH ORDINALITY
                         AS v(source_id, is_valid, exit_ip, ordinal)
                 ), resolved AS (
                    SELECT DISTINCT ON (membership.definition_id)
                           membership.definition_id, input.exit_ip
                    FROM input
                    JOIN subscription_proxies membership
                      ON membership.source_proxy_id = input.source_id
                    WHERE input.is_valid = TRUE
                      AND zenproxy_try_inet(input.exit_ip) IS NOT NULL
                    ORDER BY membership.definition_id, input.ordinal DESC
                 )
                 INSERT INTO proxy_exit (
                    definition_id, ip_address, observed_at, observation_count
                 )
                 SELECT definition_id, zenproxy_try_inet(exit_ip), NOW(), 1
                 FROM resolved
                 ON CONFLICT (definition_id) DO UPDATE SET
                    ip_address = EXCLUDED.ip_address,
                    observed_at = EXCLUDED.observed_at,
                    observation_count = proxy_exit.observation_count + 1",
                &[&source_ids, &valid, &exit_ips],
            )?;

            let invalid_ids: Vec<_> = applied
                .iter()
                .filter(|result| !result.is_valid)
                .map(|result| result.proxy_id.clone())
                .collect();
            if !invalid_ids.is_empty() {
                let deleted_rows = tx.query(
                    "DELETE FROM subscription_proxies
                     WHERE source_proxy_id = ANY($1::text[])
                       AND orphaned_at IS NOT NULL
                     RETURNING source_proxy_id, definition_id",
                    &[&invalid_ids],
                )?;
                let deleted: std::collections::HashSet<String> = deleted_rows
                    .iter()
                    .map(|row| row.get::<_, String>(0))
                    .collect();
                let deleted_definition_ids: Vec<String> =
                    deleted_rows.iter().map(|row| row.get(1)).collect();
                delete_unreferenced_definitions(&mut tx, &deleted_definition_ids)?;
                for result in &mut applied {
                    result.deleted_orphan = deleted.contains(&result.proxy_id);
                }
            }

            tx.commit()?;
            Ok(applied)
        })
    }

    /// Save the exit address observed during validation without erasing richer
    /// country/risk/capability fields collected by the quality checker.
    pub fn upsert_proxy_exit_ip(
        &self,
        proxy_id: &str,
        exit_ip: &str,
    ) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO proxy_exit (
                    definition_id, ip_address, observed_at, observation_count
                 )
                 SELECT membership.definition_id, zenproxy_try_inet($2), NOW(), 1
                 FROM subscription_proxies membership
                 WHERE membership.source_proxy_id = $1
                   AND zenproxy_try_inet($2) IS NOT NULL
                 ON CONFLICT (definition_id) DO UPDATE SET
                    ip_address = EXCLUDED.ip_address,
                    observed_at = EXCLUDED.observed_at,
                    observation_count = proxy_exit.observation_count + 1",
                &[&proxy_id, &exit_ip],
            )?;
            Ok(())
        })
    }

    pub fn mark_proxy_relay_failed(
        &self,
        id: &str,
        error: &str,
        unhealthy_threshold: u32,
    ) -> Result<(), postgres::Error> {
        let err = error.to_string();
        let unhealthy_threshold = unhealthy_threshold.max(1).min(i32::MAX as u32) as i32;
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            tx.execute(
                "UPDATE proxy_health health
                 SET health_state = CASE
                         WHEN health.consecutive_failures + 1 >= $3 THEN 'unhealthy'
                         ELSE 'suspect'
                     END,
                     consecutive_failures = health.consecutive_failures + 1,
                     last_failure_at = NOW(),
                     next_check_at = CASE
                         WHEN health.consecutive_failures + 1 >= $3
                             THEN NOW() + INTERVAL '12 hours'
                         ELSE NOW() + CASE
                             WHEN health.consecutive_failures + 1 <= 1 THEN INTERVAL '5 minutes'
                             WHEN health.consecutive_failures + 1 = 2 THEN INTERVAL '15 minutes'
                             WHEN health.consecutive_failures + 1 = 3 THEN INTERVAL '60 minutes'
                             ELSE INTERVAL '180 minutes'
                         END
                     END,
                     failure_kind = 'relay_failure',
                     last_error = $1,
                     lease_owner = NULL,
                     lease_until = NULL,
                     updated_at = NOW()
                 FROM subscription_proxies membership
                 WHERE membership.source_proxy_id = $2
                   AND health.definition_id = membership.definition_id",
                &[&err, &id, &unhealthy_threshold],
            )?;
            tx.execute(
                "UPDATE proxy_runtime runtime
                 SET local_port = NULL, binding_owner_id = NULL, updated_at = NOW()
                 FROM subscription_proxies membership
                 WHERE membership.source_proxy_id = $1
                   AND runtime.definition_id = membership.definition_id",
                &[&id],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn reset_proxy_to_untested(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            tx.execute(
                "UPDATE proxy_health health
                 SET health_state = 'untested', consecutive_failures = 0,
                     last_success_at = NULL, last_failure_at = NULL,
                     next_check_at = NOW(), failure_kind = NULL,
                     last_error = NULL, lease_owner = NULL, lease_until = NULL,
                     updated_at = NOW()
                 FROM subscription_proxies membership
                 WHERE membership.source_proxy_id = $1
                   AND health.definition_id = membership.definition_id",
                &[&id],
            )?;
            tx.execute(
                "UPDATE proxy_runtime runtime
                 SET local_port = NULL, binding_owner_id = NULL, updated_at = NOW()
                 FROM subscription_proxies membership
                 WHERE membership.source_proxy_id = $1
                   AND runtime.definition_id = membership.definition_id",
                &[&id],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn update_proxy_local_port(
        &self,
        id: &str,
        local_port: i32,
    ) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "WITH resolved AS (
                    SELECT definition_id
                    FROM subscription_proxies
                    WHERE source_proxy_id = $2
                 ), updated_runtime AS (
                    UPDATE proxy_runtime runtime
                    SET local_port = $1, binding_owner_id = $2,
                        binding_failure_count = 0,
                        last_binding_failure = NULL,
                        updated_at = NOW()
                    FROM resolved
                    WHERE runtime.definition_id = resolved.definition_id
                    RETURNING runtime.definition_id
                 )
                 UPDATE proxy_health health
                 SET failure_kind = NULL, last_error = NULL, updated_at = NOW()
                 FROM updated_runtime
                 WHERE health.definition_id = updated_runtime.definition_id
                   AND health.failure_kind = 'binding_unavailable'",
                &[&local_port, &id],
            )?;
            Ok(())
        })
    }

    pub fn get_proxy_binding_owner(
        &self,
        id: &str,
    ) -> Result<Option<String>, postgres::Error> {
        self.with_conn(|conn| {
            Ok(conn
                .query_opt(
                    "SELECT runtime.binding_owner_id
                     FROM proxy_runtime runtime
                     JOIN subscription_proxies membership
                       ON membership.definition_id = runtime.definition_id
                     WHERE membership.source_proxy_id = $1",
                    &[&id],
                )?
                .and_then(|row| row.get(0)))
        })
    }

    /// Persist one complete binding reconciliation with at most two UPDATEs.
    /// `local_port` is runtime state, so this deliberately does not change
    /// health scheduling timestamps.
    pub fn sync_proxy_local_ports(
        &self,
        assignments: &[(String, u16)],
        cleared_ids: &[String],
    ) -> Result<(), postgres::Error> {
        if assignments.is_empty() && cleared_ids.is_empty() {
            return Ok(());
        }
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            if !assignments.is_empty() {
                let ids: Vec<_> = assignments.iter().map(|(id, _)| id.clone()).collect();
                let ports: Vec<_> = assignments
                    .iter()
                    .map(|(_, port)| i32::from(*port))
                    .collect();
                tx.execute(
                    "WITH input AS (
                        SELECT *
                        FROM UNNEST($1::text[], $2::int[])
                             WITH ORDINALITY AS v(source_id, local_port, ordinal)
                     ), resolved AS (
                        SELECT DISTINCT ON (membership.definition_id)
                               membership.definition_id, input.source_id,
                               input.local_port
                        FROM input
                        JOIN subscription_proxies membership
                          ON membership.source_proxy_id = input.source_id
                        ORDER BY membership.definition_id, input.ordinal DESC
                     ),
                     updated_runtime AS (
                        UPDATE proxy_runtime runtime
                        SET local_port = resolved.local_port,
                            binding_owner_id = resolved.source_id,
                            binding_failure_count = 0,
                            last_binding_failure = NULL,
                            updated_at = NOW()
                        FROM resolved
                        WHERE runtime.definition_id = resolved.definition_id
                        RETURNING runtime.definition_id
                     )
                     UPDATE proxy_health health
                     SET failure_kind = NULL, last_error = NULL, updated_at = NOW()
                     FROM updated_runtime
                     WHERE health.definition_id = updated_runtime.definition_id
                       AND health.failure_kind = 'binding_unavailable'",
                    &[&ids, &ports],
                )?;
            }
            if !cleared_ids.is_empty() {
                let assigned_ids: Vec<String> =
                    assignments.iter().map(|(id, _)| id.clone()).collect();
                tx.execute(
                    "WITH assigned AS (
                        SELECT DISTINCT membership.definition_id
                        FROM subscription_proxies membership
                        WHERE membership.source_proxy_id = ANY($2::text[])
                     ), cleared AS (
                        SELECT DISTINCT membership.definition_id
                        FROM subscription_proxies membership
                        WHERE membership.source_proxy_id = ANY($1::text[])
                     )
                     UPDATE proxy_runtime runtime
                     SET local_port = NULL, binding_owner_id = NULL, updated_at = NOW()
                     FROM cleared
                     WHERE runtime.definition_id = cleared.definition_id
                       AND NOT EXISTS (
                           SELECT 1 FROM assigned
                           WHERE assigned.definition_id = cleared.definition_id
                       )",
                    &[&cleared_ids, &assigned_ids],
                )?;
            }
            tx.commit()
        })
    }

    pub fn increment_proxy_error_count(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxy_health health
                 SET health_state = 'suspect',
                     consecutive_failures = health.consecutive_failures + 1,
                     last_failure_at = NOW(), next_check_at = NOW(), updated_at = NOW()
                 FROM subscription_proxies membership
                 WHERE membership.source_proxy_id = $1
                   AND health.definition_id = membership.definition_id",
                &[&id],
            )?;
            Ok(())
        })
    }

    /// Persist one validation wave of local binding failures separately from
    /// remote health failures. Each canonical definition is incremented once,
    /// its lease is released, and its next attempt receives bounded backoff.
    pub fn record_proxy_binding_failures(
        &self,
        ids: &[String],
    ) -> Result<Vec<(String, u32)>, postgres::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        self.with_conn(|conn| {
            let rows = conn.query(
                "WITH input AS (
                    SELECT source_id, ordinal
                    FROM UNNEST($1::text[])
                         WITH ORDINALITY AS value(source_id, ordinal)
                 ), resolved AS (
                    SELECT DISTINCT ON (membership.definition_id)
                           membership.definition_id, input.source_id, input.ordinal
                    FROM input
                    JOIN subscription_proxies membership
                      ON membership.source_proxy_id = input.source_id
                    ORDER BY membership.definition_id, input.ordinal
                 ), updated_runtime AS (
                    UPDATE proxy_runtime runtime
                    SET binding_failure_count = runtime.binding_failure_count + 1,
                        last_binding_failure = NOW(), local_port = NULL,
                        binding_owner_id = NULL, updated_at = NOW()
                    FROM resolved
                    WHERE runtime.definition_id = resolved.definition_id
                    RETURNING runtime.definition_id,
                              runtime.binding_failure_count
                 ), scheduled AS (
                    UPDATE proxy_health health
                    SET next_check_at = GREATEST(
                            health.next_check_at,
                            NOW() + CASE
                                WHEN updated_runtime.binding_failure_count <= 1
                                    THEN INTERVAL '5 minutes'
                                WHEN updated_runtime.binding_failure_count = 2
                                    THEN INTERVAL '15 minutes'
                                WHEN updated_runtime.binding_failure_count = 3
                                    THEN INTERVAL '60 minutes'
                                ELSE INTERVAL '180 minutes'
                            END
                        ),
                        failure_kind = 'binding_unavailable',
                        last_error = 'local binding allocation failed',
                        lease_owner = NULL,
                        lease_until = NULL,
                        updated_at = NOW()
                    FROM updated_runtime
                    WHERE health.definition_id = updated_runtime.definition_id
                    RETURNING health.definition_id
                 )
                 SELECT resolved.source_id,
                        updated_runtime.binding_failure_count
                 FROM resolved
                 JOIN updated_runtime USING (definition_id)
                 JOIN scheduled USING (definition_id)
                 ORDER BY resolved.ordinal",
                &[&ids],
            )?;
            Ok(rows
                .iter()
                .map(|row| {
                    let failures: i32 = row.get(1);
                    (row.get(0), failures.max(0) as u32)
                })
                .collect())
        })
    }

    pub fn mark_proxy_orphaned(&self, id: &str, orphaned_at: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE subscription_proxies
                 SET orphaned_at = COALESCE(orphaned_at, zenproxy_try_timestamptz($1)),
                     updated_at = NOW()
                 WHERE source_proxy_id = $2",
                &[&orphaned_at, &id],
            )?;
            Ok(())
        })
    }

    pub fn mark_proxies_orphaned(
        &self,
        ids: &[String],
        orphaned_at: &str,
    ) -> Result<usize, postgres::Error> {
        if ids.is_empty() {
            return Ok(0);
        }
        self.with_conn(|conn| {
            Ok(conn.execute(
                "UPDATE subscription_proxies
                 SET orphaned_at = COALESCE(orphaned_at, zenproxy_try_timestamptz($1)),
                     updated_at = NOW()
                 WHERE source_proxy_id = ANY($2::text[])",
                &[&orphaned_at, &ids],
            )? as usize)
        })
    }

    pub fn delete_proxy_if_orphaned(&self, id: &str) -> Result<bool, postgres::Error> {
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            let rows = tx.query(
                "DELETE FROM subscription_proxies
                 WHERE source_proxy_id = $1 AND orphaned_at IS NOT NULL
                 RETURNING definition_id",
                &[&id],
            )?;
            let definition_ids: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
            delete_unreferenced_definitions(&mut tx, &definition_ids)?;
            tx.commit()?;
            Ok(!rows.is_empty())
        })
    }

    pub fn update_proxy_local_port_null(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxy_runtime runtime
                 SET local_port = NULL, binding_owner_id = NULL, updated_at = NOW()
                 FROM subscription_proxies membership
                 WHERE membership.source_proxy_id = $1
                   AND runtime.definition_id = membership.definition_id",
                &[&id],
            )?;
            Ok(())
        })
    }

    pub fn clear_all_proxy_local_ports(&self) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxy_runtime
                 SET local_port = NULL, binding_owner_id = NULL, updated_at = NOW()
                 WHERE local_port IS NOT NULL",
                &[],
            )?;
            Ok(())
        })
    }

    /// Explicit administrator-requested deletion. Scheduled validation never
    /// calls this path; high-error definitions are quarantined and retained
    /// unless an operator deliberately invokes the cleanup endpoint.
    pub fn cleanup_high_error_proxies(&self, threshold: u32) -> Result<usize, postgres::Error> {
        let threshold = threshold as i32;
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            let rows = tx.query(
                "DELETE FROM subscription_proxies membership
                 USING proxy_health health
                 WHERE health.definition_id = membership.definition_id
                   AND health.consecutive_failures >= $1
                 RETURNING membership.definition_id",
                &[&threshold],
            )?;
            let definition_ids: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
            delete_unreferenced_definitions(&mut tx, &definition_ids)?;
            tx.commit()?;
            Ok(rows.len())
        })
    }

    pub fn upsert_quality(&self, q: &ProxyQuality) -> Result<(), postgres::Error> {
        self.apply_quality_outcomes(std::slice::from_ref(q))?;
        Ok(())
    }

    /// Apply one quality row per observed exit. Membership ids are expanded
    /// only in the returned result; quality is never copied per subscription.
    pub fn apply_quality_outcomes(
        &self,
        qualities: &[ProxyQuality],
    ) -> Result<Vec<AppliedProxyQuality>, postgres::Error> {
        if qualities.is_empty() {
            return Ok(Vec::new());
        }
        let source_ids: Vec<_> = qualities
            .iter()
            .map(|quality| quality.proxy_id.clone())
            .collect();
        let ip_addresses: Vec<_> = qualities
            .iter()
            .map(|quality| quality.ip_address.clone())
            .collect();
        let countries: Vec<_> = qualities
            .iter()
            .map(|quality| quality.country.clone())
            .collect();
        let ip_types: Vec<_> = qualities
            .iter()
            .map(|quality| quality.ip_type.clone())
            .collect();
        let residential: Vec<_> = qualities
            .iter()
            .map(|quality| quality.is_residential)
            .collect();
        let chatgpt: Vec<_> = qualities
            .iter()
            .map(|quality| quality.chatgpt_accessible)
            .collect();
        let google: Vec<_> = qualities
            .iter()
            .map(|quality| quality.google_accessible)
            .collect();
        let risk_scores: Vec<_> = qualities
            .iter()
            .map(|quality| quality.risk_score)
            .collect();
        let risk_levels: Vec<_> = qualities
            .iter()
            .map(|quality| quality.risk_level.clone())
            .collect();
        let extra_json: Vec<_> = qualities
            .iter()
            .map(|quality| quality.extra_json.clone())
            .collect();
        let checked_at: Vec<_> = qualities
            .iter()
            .map(|quality| quality.checked_at.clone())
            .collect();

        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            tx.execute(
                "WITH input AS (
                    SELECT *
                    FROM UNNEST($1::text[], $2::text[])
                         WITH ORDINALITY AS v(source_id, ip_address, ordinal)
                 ), resolved AS (
                    SELECT DISTINCT ON (membership.definition_id)
                           membership.definition_id, input.ip_address
                    FROM input
                    JOIN subscription_proxies membership
                      ON membership.source_proxy_id = input.source_id
                    WHERE zenproxy_try_inet(input.ip_address) IS NOT NULL
                    ORDER BY membership.definition_id, input.ordinal DESC
                 )
                 INSERT INTO proxy_exit (
                    definition_id, ip_address, observed_at, observation_count
                 )
                 SELECT definition_id, zenproxy_try_inet(ip_address), NOW(), 1
                 FROM resolved
                 ON CONFLICT (definition_id) DO UPDATE SET
                    ip_address = EXCLUDED.ip_address,
                    observed_at = EXCLUDED.observed_at,
                    observation_count = proxy_exit.observation_count + 1",
                &[&source_ids, &ip_addresses],
            )?;

            tx.execute(
                "WITH input AS (
                    SELECT *
                    FROM UNNEST(
                        $1::text[], $2::text[], $3::text[], $4::text[],
                        $5::bool[], $6::bool[], $7::bool[], $8::float8[],
                        $9::text[], $10::text[], $11::text[]
                    ) WITH ORDINALITY AS v(
                        source_id, ip_address, country, ip_type,
                        is_residential, chatgpt_accessible, google_accessible,
                        risk_score, risk_level, extra_json, checked_at, ordinal
                    )
                 ), resolved AS (
                    SELECT DISTINCT ON (zenproxy_try_inet(input.ip_address))
                           membership.definition_id, input.*
                    FROM input
                    JOIN subscription_proxies membership
                      ON membership.source_proxy_id = input.source_id
                    WHERE zenproxy_try_inet(input.ip_address) IS NOT NULL
                    ORDER BY zenproxy_try_inet(input.ip_address), input.ordinal DESC
                 )
                 INSERT INTO exit_quality (
                    ip_address, country, ip_type, is_residential,
                    chatgpt_accessible, google_accessible, risk_score,
                    risk_level, unlock_json, extra_json, checked_at,
                    source_definition_id
                 )
                 SELECT zenproxy_try_inet(ip_address), country, ip_type,
                        is_residential, chatgpt_accessible, google_accessible,
                        risk_score, risk_level,
                        COALESCE(
                            zenproxy_try_jsonb(extra_json)->'unlock',
                            jsonb_build_object(
                                'chatgpt', jsonb_build_object(
                                    'status', CASE WHEN chatgpt_accessible
                                                   THEN 'available' ELSE 'unavailable' END
                                ),
                                'google', jsonb_build_object(
                                    'status', CASE WHEN google_accessible
                                                   THEN 'available' ELSE 'unavailable' END
                                )
                            )
                        ),
                        COALESCE(zenproxy_try_jsonb(extra_json), '{}'::jsonb),
                        COALESCE(zenproxy_try_timestamptz(checked_at), NOW()),
                        definition_id
                 FROM resolved
                 ON CONFLICT (ip_address) DO UPDATE SET
                    country = EXCLUDED.country,
                    ip_type = EXCLUDED.ip_type,
                    is_residential = EXCLUDED.is_residential,
                    chatgpt_accessible = EXCLUDED.chatgpt_accessible,
                    google_accessible = EXCLUDED.google_accessible,
                    risk_score = EXCLUDED.risk_score,
                    risk_level = EXCLUDED.risk_level,
                    unlock_json = EXCLUDED.unlock_json,
                    extra_json = EXCLUDED.extra_json,
                    checked_at = EXCLUDED.checked_at,
                    source_definition_id = EXCLUDED.source_definition_id
                 WHERE exit_quality.checked_at <= EXCLUDED.checked_at",
                &[
                    &source_ids,
                    &ip_addresses,
                    &countries,
                    &ip_types,
                    &residential,
                    &chatgpt,
                    &google,
                    &risk_scores,
                    &risk_levels,
                    &extra_json,
                    &checked_at,
                ],
            )?;

            tx.execute(
                "WITH input AS (
                    SELECT *
                    FROM UNNEST($1::text[], $2::text[], $3::text[])
                         WITH ORDINALITY
                         AS v(source_id, ip_address, extra_json, ordinal)
                 ), resolved AS (
                    SELECT DISTINCT ON (membership.definition_id)
                           membership.definition_id, input.extra_json
                    FROM input
                    JOIN subscription_proxies membership
                      ON membership.source_proxy_id = input.source_id
                    WHERE zenproxy_try_inet(input.ip_address) IS NULL
                    ORDER BY membership.definition_id, input.ordinal DESC
                 )
                 INSERT INTO quality_retry_state (definition_id, extra_json, checked_at)
                 SELECT definition_id,
                        COALESCE(zenproxy_try_jsonb(extra_json), '{}'::jsonb), NOW()
                 FROM resolved
                 ON CONFLICT (definition_id) DO UPDATE SET
                    extra_json = EXCLUDED.extra_json,
                    checked_at = EXCLUDED.checked_at",
                &[&source_ids, &ip_addresses, &extra_json],
            )?;
            tx.execute(
                "DELETE FROM quality_retry_state retry
                 USING subscription_proxies membership,
                       UNNEST($1::text[], $2::text[]) AS input(source_id, ip_address)
                 WHERE membership.source_proxy_id = input.source_id
                   AND retry.definition_id = membership.definition_id
                   AND zenproxy_try_inet(input.ip_address) IS NOT NULL",
                &[&source_ids, &ip_addresses],
            )?;

            let rows = tx.query(
                "WITH input AS (
                    SELECT *
                    FROM UNNEST($1::text[], $2::text[])
                         WITH ORDINALITY AS v(source_id, ip_address, ordinal)
                 ), resolved AS (
                    SELECT membership.definition_id, input.source_id,
                           input.ip_address, input.ordinal
                    FROM input
                    JOIN subscription_proxies membership
                      ON membership.source_proxy_id = input.source_id
                 ), targets AS (
                    SELECT membership.source_proxy_id AS target_id,
                           resolved.source_id, resolved.ordinal
                    FROM resolved
                    JOIN subscription_proxies membership
                      ON membership.definition_id = resolved.definition_id
                    UNION ALL
                    SELECT membership.source_proxy_id AS target_id,
                           resolved.source_id, resolved.ordinal
                    FROM resolved
                    JOIN proxy_exit observed
                      ON observed.ip_address = zenproxy_try_inet(resolved.ip_address)
                    JOIN subscription_proxies membership
                      ON membership.definition_id = observed.definition_id
                     AND membership.orphaned_at IS NULL
                    WHERE zenproxy_try_inet(resolved.ip_address) IS NOT NULL
                 )
                 SELECT DISTINCT ON (target_id) target_id, source_id
                 FROM targets
                 ORDER BY target_id, ordinal DESC",
                &[&source_ids, &ip_addresses],
            )?;
            let applied = rows
                .iter()
                .map(|row| AppliedProxyQuality {
                    proxy_id: row.get(0),
                    source_id: row.get(1),
                })
                .collect();
            tx.commit()?;
            Ok(applied)
        })
    }

    pub fn get_quality(&self, proxy_id: &str) -> Result<Option<ProxyQuality>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT proxy_id, ip_address, country, ip_type, is_residential,
                        chatgpt_accessible, google_accessible, risk_score, risk_level,
                        extra_json, checked_at
                 FROM normalized_proxy_quality WHERE proxy_id = $1",
                &[&proxy_id],
            )?;
            Ok(row.as_ref().map(quality_from_row))
        })
    }

    pub fn get_all_qualities(&self) -> Result<Vec<ProxyQuality>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT proxy_id, ip_address, country, ip_type, is_residential,
                        chatgpt_accessible, google_accessible, risk_score, risk_level,
                        extra_json, checked_at
                 FROM normalized_proxy_quality",
                &[],
            )?;
            Ok(rows.iter().map(quality_from_row).collect())
        })
    }

    pub fn get_stats(&self) -> Result<serde_json::Value, postgres::Error> {
        self.with_conn(|conn| {
            // Keep dashboard statistics aligned with subscription export/listing:
            // orphaned proxies are internal refresh fallbacks, not current nodes.
            let proxy_counts = conn.query_one(
                "SELECT
                    COUNT(*) AS total,
                    COUNT(DISTINCT q.ip_address) FILTER (
                        WHERE p.is_valid = TRUE
                          AND q.ip_address IS NOT NULL
                          AND BTRIM(q.ip_address) <> ''
                    ) AS valid,
                    COUNT(*) FILTER (
                        WHERE p.is_valid = FALSE AND p.last_validated IS NULL
                    ) AS untested,
                    COUNT(*) FILTER (
                        WHERE p.is_valid = FALSE AND p.last_validated IS NOT NULL
                    ) AS invalid
                 FROM normalized_proxies p
                 LEFT JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                 WHERE p.orphaned_at IS NULL",
                &[],
            )?;
            let total: i64 = proxy_counts.get("total");
            let valid: i64 = proxy_counts.get("valid");
            let untested: i64 = proxy_counts.get("untested");
            let invalid: i64 = proxy_counts.get("invalid");
            let subs: i64 = conn
                .query_one("SELECT COUNT(*) FROM subscriptions", &[])?
                .get(0);
            let quality_counts = conn.query_one(
                "SELECT
                    COUNT(DISTINCT q.ip_address) AS quality_checked,
                    COUNT(DISTINCT q.ip_address) FILTER (
                        WHERE q.chatgpt_accessible = TRUE
                    ) AS chatgpt_accessible,
                    COUNT(DISTINCT q.ip_address) FILTER (
                        WHERE q.google_accessible = TRUE
                    ) AS google_accessible,
                    COUNT(DISTINCT q.ip_address) FILTER (
                        WHERE q.is_residential = TRUE
                    ) AS residential
                 FROM normalized_proxy_quality q
                 JOIN normalized_proxies p ON p.id = q.proxy_id
                 WHERE p.is_valid = TRUE
                   AND p.orphaned_at IS NULL
                   AND q.ip_address IS NOT NULL
                   AND BTRIM(q.ip_address) <> ''",
                &[],
            )?;
            let quality_checked: i64 = quality_counts.get("quality_checked");
            let chatgpt_accessible: i64 = quality_counts.get("chatgpt_accessible");
            let google_accessible: i64 = quality_counts.get("google_accessible");
            let residential: i64 = quality_counts.get("residential");

            let by_type_rows = conn.query(
                "SELECT proxy_type, COUNT(*)
                 FROM normalized_proxies
                 WHERE orphaned_at IS NULL
                 GROUP BY proxy_type",
                &[],
            )?;
            let by_country_rows = conn.query(
                "SELECT q.country, COUNT(DISTINCT q.ip_address)
                 FROM normalized_proxy_quality q
                 JOIN normalized_proxies p ON p.id = q.proxy_id
                 WHERE p.is_valid = TRUE
                   AND p.orphaned_at IS NULL
                   AND q.country IS NOT NULL
                 GROUP BY q.country
                 ORDER BY COUNT(DISTINCT q.ip_address) DESC",
                &[],
            )?;

            let by_type = by_type_rows
                .iter()
                .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)))
                .collect::<std::collections::HashMap<_, _>>();
            let by_country = by_country_rows
                .iter()
                .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)))
                .collect::<std::collections::HashMap<_, _>>();
            let integrity = conn.query_one(
                "SELECT
                    (SELECT COUNT(*)
                     FROM subscription_proxies membership
                     LEFT JOIN proxy_health health
                       ON health.definition_id = membership.definition_id
                     WHERE health.definition_id IS NULL) AS health_missing,
                    (SELECT COUNT(*)
                     FROM subscription_proxies membership
                     LEFT JOIN proxy_runtime runtime
                       ON runtime.definition_id = membership.definition_id
                     WHERE runtime.definition_id IS NULL) AS runtime_missing,
                    (SELECT COUNT(*)
                     FROM proxy_definitions definition
                     WHERE NOT EXISTS (
                         SELECT 1 FROM subscription_proxies membership
                         WHERE membership.definition_id = definition.id
                     )) AS unreferenced_definitions,
                    (SELECT COUNT(*)
                     FROM quality_retry_state retry
                     JOIN proxy_exit observed
                       ON observed.definition_id = retry.definition_id)
                        AS retry_with_exit",
                &[],
            )?;
            let health_missing: i64 = integrity.get("health_missing");
            let runtime_missing: i64 = integrity.get("runtime_missing");
            let unreferenced_definitions: i64 = integrity.get("unreferenced_definitions");
            let retry_with_exit: i64 = integrity.get("retry_with_exit");

            Ok(serde_json::json!({
                "total_proxies": total,
                "valid_proxies": valid,
                "untested_proxies": untested,
                "invalid_proxies": invalid,
                "subscriptions": subs,
                "quality_checked": quality_checked,
                "chatgpt_accessible": chatgpt_accessible,
                "google_accessible": google_accessible,
                "residential": residential,
                "by_type": by_type,
                "by_country": by_country,
                "normalization_integrity": {
                    "health_missing": health_missing,
                    "runtime_missing": runtime_missing,
                    "unreferenced_definitions": unreferenced_definitions,
                    "retry_with_exit": retry_with_exit,
                },
            }))
        })
    }

    pub fn upsert_user(&self, user: &User) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO users (
                    id, username, name, avatar_template, active, trust_level, silenced,
                    is_banned, api_key, created_at, updated_at
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7,
                    $8, $9, $10, $11
                 )
                 ON CONFLICT (id) DO UPDATE SET
                    username = EXCLUDED.username,
                    name = EXCLUDED.name,
                    avatar_template = EXCLUDED.avatar_template,
                    active = EXCLUDED.active,
                    trust_level = EXCLUDED.trust_level,
                    silenced = EXCLUDED.silenced,
                    updated_at = EXCLUDED.updated_at",
                &[
                    &user.id,
                    &user.username,
                    &user.name,
                    &user.avatar_template,
                    &user.active,
                    &user.trust_level,
                    &user.silenced,
                    &user.is_banned,
                    &user.api_key,
                    &user.created_at,
                    &user.updated_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn get_fixed_proxy_slots(
        &self,
        account_id: &str,
    ) -> Result<Vec<FixedProxySlot>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, account_id, slot_key, label, country, proxy_type,
                        residential, chatgpt, google, proxy_id, exit_ip,
                        included_in_subscription, replacement_count,
                        last_replacement_reason, last_replaced_at,
                        created_at, updated_at
                 FROM fixed_proxy_slots
                 WHERE account_id = $1
                 ORDER BY created_at, id",
                &[&account_id],
            )?;
            Ok(rows.iter().map(fixed_proxy_slot_from_row).collect())
        })
    }

    pub fn get_all_fixed_proxy_slots(&self) -> Result<Vec<FixedProxySlot>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, account_id, slot_key, label, country, proxy_type,
                        residential, chatgpt, google, proxy_id, exit_ip,
                        included_in_subscription, replacement_count,
                        last_replacement_reason, last_replaced_at,
                        created_at, updated_at
                 FROM fixed_proxy_slots
                 ORDER BY account_id, created_at, id",
                &[],
            )?;
            Ok(rows.iter().map(fixed_proxy_slot_from_row).collect())
        })
    }

    pub fn get_fixed_proxy_slot_by_key(
        &self,
        account_id: &str,
        slot_key: &str,
    ) -> Result<Option<FixedProxySlot>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, account_id, slot_key, label, country, proxy_type,
                        residential, chatgpt, google, proxy_id, exit_ip,
                        included_in_subscription, replacement_count,
                        last_replacement_reason, last_replaced_at,
                        created_at, updated_at
                 FROM fixed_proxy_slots
                 WHERE account_id = $1 AND slot_key = $2",
                &[&account_id, &slot_key],
            )?;
            Ok(row.as_ref().map(fixed_proxy_slot_from_row))
        })
    }

    pub fn get_fixed_proxy_slot_by_id(
        &self,
        account_id: &str,
        id: &str,
    ) -> Result<Option<FixedProxySlot>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, account_id, slot_key, label, country, proxy_type,
                        residential, chatgpt, google, proxy_id, exit_ip,
                        included_in_subscription, replacement_count,
                        last_replacement_reason, last_replaced_at,
                        created_at, updated_at
                 FROM fixed_proxy_slots
                 WHERE account_id = $1 AND id = $2",
                &[&account_id, &id],
            )?;
            Ok(row.as_ref().map(fixed_proxy_slot_from_row))
        })
    }

    pub fn insert_fixed_proxy_slots(
        &self,
        slots: &[FixedProxySlot],
    ) -> Result<(), postgres::Error> {
        if slots.is_empty() {
            return Ok(());
        }
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            for slot in slots {
                tx.execute(
                    "INSERT INTO fixed_proxy_slots (
                        id, account_id, slot_key, label, country, proxy_type,
                        residential, chatgpt, google, proxy_id, exit_ip,
                        included_in_subscription, replacement_count,
                        last_replacement_reason, last_replaced_at,
                        created_at, updated_at
                     ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                        $12, $13, $14, $15, $16, $17
                     )",
                    &[
                        &slot.id,
                        &slot.account_id,
                        &slot.slot_key,
                        &slot.label,
                        &slot.country,
                        &slot.proxy_type,
                        &slot.residential,
                        &slot.chatgpt,
                        &slot.google,
                        &slot.proxy_id,
                        &slot.exit_ip,
                        &slot.included_in_subscription,
                        &slot.replacement_count,
                        &slot.last_replacement_reason,
                        &slot.last_replaced_at,
                        &slot.created_at,
                        &slot.updated_at,
                    ],
                )?;
            }
            tx.commit()
        })
    }

    pub fn update_fixed_proxy_slot_settings(
        &self,
        account_id: &str,
        id: &str,
        label: Option<&str>,
        included_in_subscription: Option<bool>,
    ) -> Result<Option<FixedProxySlot>, postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "UPDATE fixed_proxy_slots SET
                    label = COALESCE($1, label),
                    included_in_subscription = COALESCE($2, included_in_subscription),
                    updated_at = $3
                 WHERE account_id = $4 AND id = $5
                 RETURNING id, account_id, slot_key, label, country, proxy_type,
                           residential, chatgpt, google, proxy_id, exit_ip,
                           included_in_subscription, replacement_count,
                           last_replacement_reason, last_replaced_at,
                           created_at, updated_at",
                &[&label, &included_in_subscription, &now, &account_id, &id],
            )?;
            Ok(row.as_ref().map(fixed_proxy_slot_from_row))
        })
    }

    pub fn update_fixed_proxy_slot_assignment(
        &self,
        account_id: &str,
        id: &str,
        proxy_id: &str,
        exit_ip: &str,
        reason: &str,
    ) -> Result<Option<FixedProxySlot>, postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "UPDATE fixed_proxy_slots SET
                    proxy_id = $1,
                    exit_ip = $2,
                    replacement_count = replacement_count + 1,
                    last_replacement_reason = $3,
                    last_replaced_at = $4,
                    updated_at = $4
                 WHERE account_id = $5 AND id = $6
                 RETURNING id, account_id, slot_key, label, country, proxy_type,
                           residential, chatgpt, google, proxy_id, exit_ip,
                           included_in_subscription, replacement_count,
                           last_replacement_reason, last_replaced_at,
                           created_at, updated_at",
                &[&proxy_id, &exit_ip, &reason, &now, &account_id, &id],
            )?;
            Ok(row.as_ref().map(fixed_proxy_slot_from_row))
        })
    }

    pub fn delete_fixed_proxy_slot(
        &self,
        account_id: &str,
        id: &str,
    ) -> Result<bool, postgres::Error> {
        self.with_conn(|conn| {
            Ok(conn.execute(
                "DELETE FROM fixed_proxy_slots WHERE account_id = $1 AND id = $2",
                &[&account_id, &id],
            )? > 0)
        })
    }

    pub fn get_or_create_fixed_subscription_version(
        &self,
        account_id: &str,
    ) -> Result<i32, postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO fixed_proxy_subscriptions (
                    account_id, token_version, created_at, updated_at
                 ) VALUES ($1, 1, $2, $2)
                 ON CONFLICT (account_id) DO NOTHING",
                &[&account_id, &now],
            )?;
            let row = conn.query_one(
                "SELECT token_version FROM fixed_proxy_subscriptions WHERE account_id = $1",
                &[&account_id],
            )?;
            Ok(row.get(0))
        })
    }

    pub fn rotate_fixed_subscription_version(
        &self,
        account_id: &str,
    ) -> Result<i32, postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            let row = conn.query_one(
                "INSERT INTO fixed_proxy_subscriptions (
                    account_id, token_version, created_at, updated_at
                 ) VALUES ($1, 2, $2, $2)
                 ON CONFLICT (account_id) DO UPDATE SET
                    token_version = fixed_proxy_subscriptions.token_version + 1,
                    updated_at = EXCLUDED.updated_at
                 RETURNING token_version",
                &[&account_id, &now],
            )?;
            Ok(row.get(0))
        })
    }

    pub fn get_proxy_accounts(&self) -> Result<Vec<ProxyAccount>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, label, username, owner_user_id, enabled, credential_version,
                        last_used_at, created_at, updated_at
                 FROM proxy_accounts ORDER BY created_at DESC",
                &[],
            )?;
            Ok(rows.iter().map(proxy_account_from_row).collect())
        })
    }

    pub fn get_proxy_account_by_id(
        &self,
        id: &str,
    ) -> Result<Option<ProxyAccount>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, label, username, owner_user_id, enabled, credential_version,
                        last_used_at, created_at, updated_at
                 FROM proxy_accounts WHERE id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(proxy_account_from_row))
        })
    }

    pub fn get_proxy_account_for_owner(
        &self,
        owner_user_id: &str,
    ) -> Result<Option<ProxyAccount>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, label, username, owner_user_id, enabled, credential_version,
                        last_used_at, created_at, updated_at
                 FROM proxy_accounts WHERE owner_user_id = $1",
                &[&owner_user_id],
            )?;
            Ok(row.as_ref().map(proxy_account_from_row))
        })
    }

    pub fn insert_proxy_account(&self, account: &ProxyAccount) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO proxy_accounts (
                    id, label, username, owner_user_id, enabled, credential_version,
                    last_used_at, created_at, updated_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                &[
                    &account.id,
                    &account.label,
                    &account.username,
                    &account.owner_user_id,
                    &account.enabled,
                    &account.credential_version,
                    &account.last_used_at,
                    &account.created_at,
                    &account.updated_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn update_proxy_account(
        &self,
        id: &str,
        label: Option<&str>,
        update_owner: bool,
        owner_user_id: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<Option<ProxyAccount>, postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "UPDATE proxy_accounts SET
                    label = COALESCE($1, label),
                    owner_user_id = CASE WHEN $2 THEN $3 ELSE owner_user_id END,
                    enabled = COALESCE($4, enabled),
                    updated_at = $5
                 WHERE id = $6
                 RETURNING id, label, username, owner_user_id, enabled, credential_version,
                           last_used_at, created_at, updated_at",
                &[&label, &update_owner, &owner_user_id, &enabled, &now, &id],
            )?;
            Ok(row.as_ref().map(proxy_account_from_row))
        })
    }

    pub fn rotate_proxy_account(&self, id: &str) -> Result<Option<ProxyAccount>, postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "UPDATE proxy_accounts SET
                    credential_version = credential_version + 1,
                    updated_at = $1
                 WHERE id = $2
                 RETURNING id, label, username, owner_user_id, enabled, credential_version,
                           last_used_at, created_at, updated_at",
                &[&now, &id],
            )?;
            Ok(row.as_ref().map(proxy_account_from_row))
        })
    }

    pub fn delete_proxy_account(&self, id: &str) -> Result<bool, postgres::Error> {
        self.with_conn(|conn| {
            Ok(conn.execute("DELETE FROM proxy_accounts WHERE id = $1", &[&id])? > 0)
        })
    }

    pub fn touch_proxy_account_last_used(&self, id: &str) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxy_accounts SET last_used_at = $1 WHERE id = $2",
                &[&now, &id],
            )?;
            Ok(())
        })
    }

    pub fn get_user_by_id(&self, id: &str) -> Result<Option<User>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, username, name, avatar_template, active, trust_level, silenced,
                        is_banned, api_key, created_at, updated_at
                 FROM users WHERE id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(user_from_row))
        })
    }

    pub fn get_user_by_api_key(&self, api_key: &str) -> Result<Option<User>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, username, name, avatar_template, active, trust_level, silenced,
                        is_banned, api_key, created_at, updated_at
                 FROM users WHERE api_key = $1",
                &[&api_key],
            )?;
            Ok(row.as_ref().map(user_from_row))
        })
    }

    pub fn get_all_users(&self) -> Result<Vec<User>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, username, name, avatar_template, active, trust_level, silenced,
                        is_banned, api_key, created_at, updated_at
                 FROM users ORDER BY created_at DESC",
                &[],
            )?;
            Ok(rows.iter().map(user_from_row).collect())
        })
    }

    pub fn delete_user(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM sessions WHERE user_id = $1", &[&id])?;
            conn.execute("DELETE FROM users WHERE id = $1", &[&id])?;
            Ok(())
        })
    }

    pub fn set_user_banned(&self, id: &str, banned: bool) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE users SET is_banned = $1, updated_at = $2 WHERE id = $3",
                &[&banned, &now, &id],
            )?;
            if banned {
                conn.execute("DELETE FROM sessions WHERE user_id = $1", &[&id])?;
            }
            Ok(())
        })
    }

    pub fn regenerate_api_key(&self, user_id: &str) -> Result<String, postgres::Error> {
        let new_key = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE users SET api_key = $1, updated_at = $2 WHERE id = $3",
                &[&new_key, &now, &user_id],
            )?;
            Ok(new_key)
        })
    }

    pub fn create_session(&self, user_id: &str) -> Result<Session, postgres::Error> {
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::days(7);
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        };
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO sessions (id, user_id, created_at, expires_at)
                 VALUES ($1, $2, $3, $4)",
                &[
                    &session.id,
                    &session.user_id,
                    &session.created_at,
                    &session.expires_at,
                ],
            )?;
            Ok(session)
        })
    }

    pub fn get_session(&self, id: &str) -> Result<Option<Session>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(session_from_row))
        })
    }

    pub fn delete_session(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM sessions WHERE id = $1", &[&id])?;
            Ok(())
        })
    }

    pub fn delete_user_sessions(&self, user_id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM sessions WHERE user_id = $1", &[&user_id])?;
            Ok(())
        })
    }

    pub fn cleanup_expired_sessions(&self) -> Result<usize, postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            let count = conn.execute("DELETE FROM sessions WHERE expires_at < $1", &[&now])?;
            Ok(count as usize)
        })
    }
}

fn subscription_from_row(row: &Row) -> Subscription {
    Subscription {
        id: row.get(0),
        name: row.get(1),
        sub_type: row.get(2),
        url: row.get(3),
        content: row.get(4),
        proxy_count: row.get(5),
        raw_proxy_count: row.get(6),
        duplicate_proxy_count: row.get(7),
        refresh_interval_mins: row.get(8),
        last_refresh_at: row.get(9),
        created_at: row.get(10),
        updated_at: row.get(11),
    }
}

fn proxy_definition_hash(proxy: &ProxyRow) -> Vec<u8> {
    proxy_definition_hash_from_config(
        &proxy.id,
        &proxy.proxy_type,
        &proxy.server,
        proxy.port,
        &proxy.config_json,
    )
}

fn upsert_proxy_rows_tx(
    tx: &mut postgres::Transaction<'_>,
    proxies: &[ProxyRow],
) -> Result<u64, postgres::Error> {
    let ids: Vec<_> = proxies.iter().map(|proxy| proxy.id.clone()).collect();
    let previous_definition_ids: Vec<String> = tx
        .query(
            "SELECT DISTINCT definition_id
             FROM subscription_proxies
             WHERE source_proxy_id = ANY($1::text[])",
            &[&ids],
        )?
        .iter()
        .map(|row| row.get(0))
        .collect();
    let subscription_ids: Vec<_> = proxies
        .iter()
        .map(|proxy| proxy.subscription_id.clone())
        .collect();
    let names: Vec<_> = proxies.iter().map(|proxy| proxy.name.clone()).collect();
    let proxy_types: Vec<_> = proxies
        .iter()
        .map(|proxy| proxy.proxy_type.clone())
        .collect();
    let servers: Vec<_> = proxies.iter().map(|proxy| proxy.server.clone()).collect();
    let ports: Vec<_> = proxies.iter().map(|proxy| proxy.port).collect();
    let configs: Vec<_> = proxies
        .iter()
        .map(|proxy| proxy.config_json.clone())
        .collect();
    let hashes: Vec<_> = proxies.iter().map(proxy_definition_hash).collect();
    let valid: Vec<_> = proxies.iter().map(|proxy| proxy.is_valid).collect();
    let local_ports: Vec<_> = proxies.iter().map(|proxy| proxy.local_port).collect();
    let error_counts: Vec<_> = proxies.iter().map(|proxy| proxy.error_count).collect();
    let last_errors: Vec<_> = proxies
        .iter()
        .map(|proxy| proxy.last_error.clone())
        .collect();
    let last_validated: Vec<_> = proxies
        .iter()
        .map(|proxy| proxy.last_validated.clone())
        .collect();
    let created_at: Vec<_> = proxies
        .iter()
        .map(|proxy| proxy.created_at.clone())
        .collect();
    let updated_at: Vec<_> = proxies
        .iter()
        .map(|proxy| proxy.updated_at.clone())
        .collect();
    let orphaned_at: Vec<_> = proxies
        .iter()
        .map(|proxy| proxy.orphaned_at.clone())
        .collect();

    let updated = tx.execute(
        "WITH input AS MATERIALIZED (
            SELECT * FROM UNNEST(
                $1::text[], $2::text[], $3::text[], $4::text[],
                $5::text[], $6::int4[], $7::text[], $8::bytea[],
                $9::bool[], $10::int4[], $11::int4[], $12::text[],
                $13::text[], $14::text[], $15::text[], $16::text[]
            ) WITH ORDINALITY AS v(
                id, subscription_id, name, proxy_type, server, port, config_json,
                definition_hash, is_valid, local_port, error_count, last_error,
                last_validated, created_at, updated_at, orphaned_at, ordinal
            )
         ), selected_definitions AS (
            SELECT DISTINCT ON (definition_hash) *
            FROM input
            ORDER BY definition_hash, ordinal DESC
         ), definitions AS (
            INSERT INTO proxy_definitions (
                id, identity_version, definition_hash, proxy_type, server, port,
                config_json, created_at, updated_at
            )
            SELECT gen_random_uuid()::text, 1, definition_hash, proxy_type,
                   server, port, COALESCE(zenproxy_try_jsonb(config_json), '{}'::jsonb),
                   COALESCE(zenproxy_try_timestamptz(created_at), NOW()),
                   COALESCE(zenproxy_try_timestamptz(updated_at), NOW())
            FROM selected_definitions
            ON CONFLICT (definition_hash) DO UPDATE SET
                proxy_type = EXCLUDED.proxy_type,
                server = EXCLUDED.server,
                port = EXCLUDED.port,
                config_json = EXCLUDED.config_json,
                updated_at = GREATEST(proxy_definitions.updated_at, EXCLUDED.updated_at)
            RETURNING id, definition_hash
         ), memberships AS (
            INSERT INTO subscription_proxies (
                source_proxy_id, subscription_id, definition_id, display_name,
                orphaned_at, created_at, updated_at
            )
            SELECT input.id, input.subscription_id, definitions.id, input.name,
                   zenproxy_try_timestamptz(input.orphaned_at),
                   COALESCE(zenproxy_try_timestamptz(input.created_at), NOW()),
                   COALESCE(zenproxy_try_timestamptz(input.updated_at), NOW())
            FROM input
            JOIN definitions USING (definition_hash)
            ON CONFLICT (source_proxy_id) DO UPDATE SET
                subscription_id = EXCLUDED.subscription_id,
                definition_id = EXCLUDED.definition_id,
                display_name = EXCLUDED.display_name,
                orphaned_at = EXCLUDED.orphaned_at,
                updated_at = EXCLUDED.updated_at
            RETURNING definition_id
         ), health AS (
            INSERT INTO proxy_health (
                definition_id, health_state, consecutive_failures,
                last_success_at, last_failure_at, next_check_at,
                failure_kind, last_error, updated_at
            )
            SELECT definitions.id,
                   CASE
                       WHEN selected.is_valid THEN 'healthy'
                       WHEN selected.last_validated IS NULL AND selected.error_count = 0
                           THEN 'untested'
                       ELSE 'suspect'
                   END,
                   GREATEST(selected.error_count, 0),
                   CASE WHEN selected.is_valid
                        THEN zenproxy_try_timestamptz(selected.last_validated) END,
                   CASE WHEN NOT selected.is_valid
                        THEN zenproxy_try_timestamptz(selected.last_validated) END,
                   CASE
                       WHEN selected.last_validated IS NULL THEN NOW()
                       WHEN selected.is_valid THEN NOW() + INTERVAL '30 minutes'
                       ELSE NOW() + INTERVAL '5 minutes'
                   END,
                   CASE WHEN selected.is_valid OR selected.last_validated IS NULL
                        THEN NULL ELSE 'imported_failure' END,
                   selected.last_error,
                   COALESCE(zenproxy_try_timestamptz(selected.updated_at), NOW())
            FROM selected_definitions selected
            JOIN definitions ON definitions.definition_hash = selected.definition_hash
            ON CONFLICT (definition_id) DO NOTHING
            RETURNING definition_id
         )
         INSERT INTO proxy_runtime (
            definition_id, local_port, binding_owner_id, binding_failure_count,
            last_binding_failure, updated_at
         )
         SELECT definitions.id, selected.local_port,
                CASE WHEN selected.local_port IS NULL THEN NULL ELSE selected.id END,
                0, NULL,
                COALESCE(zenproxy_try_timestamptz(selected.updated_at), NOW())
         FROM selected_definitions selected
         JOIN definitions ON definitions.definition_hash = selected.definition_hash
         ON CONFLICT (definition_id) DO NOTHING",
        &[
            &ids,
            &subscription_ids,
            &names,
            &proxy_types,
            &servers,
            &ports,
            &configs,
            &hashes,
            &valid,
            &local_ports,
            &error_counts,
            &last_errors,
            &last_validated,
            &created_at,
            &updated_at,
            &orphaned_at,
        ],
    )?;
    delete_unreferenced_definitions(tx, &previous_definition_ids)?;
    Ok(updated)
}

fn delete_unreferenced_definitions(
    tx: &mut postgres::Transaction<'_>,
    definition_ids: &[String],
) -> Result<u64, postgres::Error> {
    if definition_ids.is_empty() {
        return Ok(0);
    }
    tx.execute(
        "DELETE FROM proxy_definitions definition
         WHERE definition.id = ANY($1::text[])
           AND NOT EXISTS (
               SELECT 1 FROM subscription_proxies membership
               WHERE membership.definition_id = definition.id
           )",
        &[&definition_ids],
    )
}

fn proxy_definition_hash_from_config(
    id: &str,
    proxy_type: &str,
    server: &str,
    port: i32,
    config_json: &str,
) -> Vec<u8> {
    let definition = serde_json::from_str::<serde_json::Value>(config_json)
        .map(|outbound| {
            crate::api::subscription::outbound_definition_key(
                proxy_type,
                server,
                port as u16,
                &outbound,
            )
        })
        .unwrap_or_else(|_| format!("invalid\u{1f}{id}"));
    Sha256::digest(definition.as_bytes()).to_vec()
}

fn proxy_from_row(row: &Row) -> ProxyRow {
    ProxyRow {
        id: row.get(0),
        subscription_id: row.get(1),
        name: row.get(2),
        proxy_type: row.get(3),
        server: row.get(4),
        port: row.get(5),
        config_json: row.get(6),
        is_valid: row.get(7),
        local_port: row.get(8),
        error_count: row.get(9),
        last_error: row.get(10),
        last_validated: row.get(11),
        created_at: row.get(12),
        updated_at: row.get(13),
        orphaned_at: row.get(14),
    }
}

fn proxy_from_join_row(row: &Row) -> ProxyRow {
    ProxyRow {
        id: row.get(0),
        subscription_id: row.get(1),
        name: row.get(2),
        proxy_type: row.get(3),
        server: row.get(4),
        port: row.get(5),
        config_json: row.get(6),
        is_valid: row.get(7),
        local_port: row.get(8),
        error_count: row.get(9),
        last_error: row.get(10),
        last_validated: row.get(11),
        created_at: row.get(12),
        updated_at: row.get(13),
        orphaned_at: row.get(14),
    }
}

fn quality_from_join_row(row: &Row, start: usize) -> Option<ProxyQuality> {
    let proxy_id: Option<String> = row.get(start);
    proxy_id.map(|proxy_id| ProxyQuality {
        proxy_id,
        ip_address: row.get(start + 1),
        country: row.get(start + 2),
        ip_type: row.get(start + 3),
        is_residential: row.get(start + 4),
        chatgpt_accessible: row.get(start + 5),
        google_accessible: row.get(start + 6),
        risk_score: row.get(start + 7),
        risk_level: row.get(start + 8),
        extra_json: row.get(start + 9),
        checked_at: row.get(start + 10),
    })
}

fn proxy_record_from_join_row(row: &Row) -> (ProxyRow, Option<ProxyQuality>) {
    (proxy_from_join_row(row), quality_from_join_row(row, 15))
}

fn quality_from_row(row: &Row) -> ProxyQuality {
    ProxyQuality {
        proxy_id: row.get(0),
        ip_address: row.get(1),
        country: row.get(2),
        ip_type: row.get(3),
        is_residential: row.get(4),
        chatgpt_accessible: row.get(5),
        google_accessible: row.get(6),
        risk_score: row.get(7),
        risk_level: row.get(8),
        extra_json: row.get(9),
        checked_at: row.get(10),
    }
}

fn user_from_row(row: &Row) -> User {
    User {
        id: row.get(0),
        username: row.get(1),
        name: row.get(2),
        avatar_template: row.get(3),
        active: row.get(4),
        trust_level: row.get(5),
        silenced: row.get(6),
        is_banned: row.get(7),
        api_key: row.get(8),
        created_at: row.get(9),
        updated_at: row.get(10),
    }
}

fn proxy_account_from_row(row: &Row) -> ProxyAccount {
    ProxyAccount {
        id: row.get(0),
        label: row.get(1),
        username: row.get(2),
        owner_user_id: row.get(3),
        enabled: row.get(4),
        credential_version: row.get(5),
        last_used_at: row.get(6),
        created_at: row.get(7),
        updated_at: row.get(8),
    }
}

fn fixed_proxy_slot_from_row(row: &Row) -> FixedProxySlot {
    FixedProxySlot {
        id: row.get(0),
        account_id: row.get(1),
        slot_key: row.get(2),
        label: row.get(3),
        country: row.get(4),
        proxy_type: row.get(5),
        residential: row.get(6),
        chatgpt: row.get(7),
        google: row.get(8),
        proxy_id: row.get(9),
        exit_ip: row.get(10),
        included_in_subscription: row.get(11),
        replacement_count: row.get(12),
        last_replacement_reason: row.get(13),
        last_replaced_at: row.get(14),
        created_at: row.get(15),
        updated_at: row.get(16),
    }
}

fn session_from_row(row: &Row) -> Session {
    Session {
        id: row.get(0),
        user_id: row.get(1),
        created_at: row.get(2),
        expires_at: row.get(3),
    }
}

impl DatabaseTimingMetrics {
    fn observe(&self, waited: Duration, query: Duration) {
        let wait_us = duration_us(waited);
        let query_us = duration_us(query);
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.wait_total_us.fetch_add(wait_us, Ordering::Relaxed);
        self.query_total_us.fetch_add(query_us, Ordering::Relaxed);
        self.wait_max_us.fetch_max(wait_us, Ordering::Relaxed);
        self.query_max_us.fetch_max(query_us, Ordering::Relaxed);
        observe_bucket(&self.wait_buckets, wait_us);
        observe_bucket(&self.query_buckets, query_us);
    }

    fn snapshot(&self) -> DatabaseRuntimeMetrics {
        let calls = self.calls.load(Ordering::Relaxed);
        let divisor = calls.max(1) as f64;
        let wait_max_us = self.wait_max_us.load(Ordering::Relaxed);
        let query_max_us = self.query_max_us.load(Ordering::Relaxed);
        DatabaseRuntimeMetrics {
            calls,
            wait_avg_ms: self.wait_total_us.load(Ordering::Relaxed) as f64 / divisor / 1000.0,
            wait_p99_upper_ms: percentile_upper_ms(&self.wait_buckets, calls, 99, wait_max_us),
            wait_max_ms: wait_max_us as f64 / 1000.0,
            query_avg_ms: self.query_total_us.load(Ordering::Relaxed) as f64 / divisor / 1000.0,
            query_p99_upper_ms: percentile_upper_ms(&self.query_buckets, calls, 99, query_max_us),
            query_max_ms: query_max_us as f64 / 1000.0,
        }
    }
}

fn duration_us(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn observe_bucket(buckets: &[AtomicU64; LATENCY_BUCKET_UPPER_US.len()], value_us: u64) {
    let index = LATENCY_BUCKET_UPPER_US
        .iter()
        .position(|upper| value_us <= *upper)
        .unwrap_or(LATENCY_BUCKET_UPPER_US.len() - 1);
    buckets[index].fetch_add(1, Ordering::Relaxed);
}

fn percentile_upper_ms(
    buckets: &[AtomicU64; LATENCY_BUCKET_UPPER_US.len()],
    count: u64,
    percentile: u64,
    observed_max_us: u64,
) -> f64 {
    if count == 0 {
        return 0.0;
    }
    let target = count.saturating_mul(percentile).div_ceil(100);
    let mut cumulative = 0u64;
    for (index, bucket) in buckets.iter().enumerate() {
        cumulative = cumulative.saturating_add(bucket.load(Ordering::Relaxed));
        if cumulative >= target {
            let upper = LATENCY_BUCKET_UPPER_US[index];
            return if upper == u64::MAX {
                observed_max_us as f64 / 1000.0
            } else {
                upper as f64 / 1000.0
            };
        }
    }
    observed_max_us as f64 / 1000.0
}

fn proxy_list_item_from_row(row: &Row) -> ProxyListItem {
    let is_valid: bool = row.get(8);
    let last_validated: Option<String> = row.get(9);
    let quality = quality_from_join_row(row, 10);
    let status = if is_valid {
        "valid"
    } else if last_validated.is_some() {
        "invalid"
    } else {
        "untested"
    };

    ProxyListItem {
        id: row.get(0),
        subscription_id: row.get(1),
        name: row.get(2),
        proxy_type: row.get(3),
        server: row.get(4),
        port: row.get(5),
        local_port: row.get(6),
        status: status.to_string(),
        error_count: row.get(7),
        quality,
    }
}

fn build_proxy_list_where(
    query: &ProxyListQuery,
    params: &mut Vec<Box<dyn ToSql + Sync>>,
) -> String {
    // Orphaned rows exist only as a short-lived refresh fallback. They are not
    // part of the current subscription and are excluded from export as well.
    let mut conditions = vec!["p.orphaned_at IS NULL".to_string()];

    if query.unique_exit_ip {
        conditions.push(
            "(
                q.ip_address IS NULL
                OR BTRIM(q.ip_address) = ''
                OR p.id IN (
                    SELECT ranked.id
                    FROM (
                        SELECT candidate.id,
                               ROW_NUMBER() OVER (
                                   PARTITION BY quality.ip_address
                                   ORDER BY candidate.is_valid DESC,
                                            candidate.error_count ASC,
                                            candidate.last_validated_ts DESC NULLS LAST,
                                            candidate.updated_at_ts DESC NULLS LAST,
                                            candidate.id ASC
                               ) AS exit_rank
                        FROM normalized_proxies candidate
                        JOIN normalized_proxy_quality quality ON quality.proxy_id = candidate.id
                        WHERE candidate.orphaned_at IS NULL
                          AND quality.ip_address IS NOT NULL
                          AND BTRIM(quality.ip_address) <> ''
                    ) ranked
                    WHERE ranked.exit_rank = 1
                )
            )"
            .to_string(),
        );
    }

    if let Some(search) = query
        .search
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        params.push(Box::new(format!("%{search}%")));
        let idx = params.len();
        conditions.push(format!(
            "(p.name ILIKE ${idx} OR p.server ILIKE ${idx} OR COALESCE(q.ip_address, '') ILIKE ${idx})"
        ));
    }

    if let Some(status) = query.status.as_deref() {
        match status {
            "valid" => conditions.push("p.is_valid = TRUE".to_string()),
            "invalid" => {
                conditions.push("p.is_valid = FALSE AND p.last_validated IS NOT NULL".to_string())
            }
            "untested" => {
                conditions.push("p.is_valid = FALSE AND p.last_validated IS NULL".to_string())
            }
            _ => {}
        }
    }

    if let Some(subscription_id) = query
        .subscription_id
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        params.push(Box::new(subscription_id.to_string()));
        let idx = params.len();
        conditions.push(format!("p.subscription_id = ${idx}"));
    }

    if let Some(proxy_type) = query
        .proxy_type
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        params.push(Box::new(proxy_type.to_string()));
        let idx = params.len();
        conditions.push(format!("p.proxy_type = ${idx}"));
    }

    if let Some(quality) = query.quality.as_deref() {
        match quality {
            "chatgpt" => conditions.push("q.chatgpt_accessible = TRUE".to_string()),
            "google" => conditions.push("q.google_accessible = TRUE".to_string()),
            "residential" => conditions.push("q.is_residential = TRUE".to_string()),
            "unchecked" => conditions.push("q.proxy_id IS NULL".to_string()),
            _ => {}
        }
    }

    if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    }
}

fn parse_rfc3339_utc(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn proxy_list_sort_expr(sort: Option<&str>) -> &'static str {
    match sort {
        Some("type") => "p.proxy_type",
        Some("server") => "p.server",
        Some("status") | Some("is_valid") => {
            "CASE WHEN p.is_valid THEN 0 WHEN p.last_validated IS NULL THEN 1 ELSE 2 END"
        }
        Some("error_count") => "p.error_count",
        Some("country") => "COALESCE(q.country, 'ZZZ')",
        Some("risk") => "COALESCE(q.risk_score, 2.0)",
        _ => "p.name",
    }
}

fn proxy_list_sort_key(sort: Option<&str>) -> &'static str {
    match sort {
        Some("type") => "type",
        Some("server") => "server",
        Some("status") | Some("is_valid") => "status",
        Some("error_count") => "error_count",
        Some("country") => "country",
        Some("risk") => "risk",
        _ => "name",
    }
}

fn encode_proxy_list_cursor(cursor: &ProxyListCursor) -> Option<String> {
    let bytes = serde_json::to_vec(cursor).ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_proxy_list_cursor(encoded: &str) -> Option<ProxyListCursor> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn build_proxy_cursor_clause(
    cursor: &ProxyListCursor,
    sort_expr: &str,
    sort_key: &str,
    dir: &str,
    backwards: bool,
    params: &mut Vec<Box<dyn ToSql + Sync>>,
) -> String {
    match sort_key {
        "status" | "error_count" => {
            let Ok(value) = cursor.value.parse::<i32>() else {
                return String::new();
            };
            params.push(Box::new(value));
        }
        "risk" => {
            let Ok(value) = cursor.value.parse::<f64>() else {
                return String::new();
            };
            params.push(Box::new(value));
        }
        _ => params.push(Box::new(cursor.value.clone())),
    }
    let value_idx = params.len();
    params.push(Box::new(cursor.id.clone()));
    let id_idx = params.len();
    let value_op = if (dir == "ASC") ^ backwards { ">" } else { "<" };
    // Tie-breaker direction follows the effective page traversal direction,
    // including when the primary sort itself is DESC.
    let id_op = if (dir == "ASC") ^ backwards { ">" } else { "<" };
    format!(
        "AND (({sort_expr}) {value_op} ${value_idx} OR (({sort_expr}) = ${value_idx} AND p.id {id_op} ${id_idx}))"
    )
}

fn proxy_cursor_value_is_valid(cursor: &ProxyListCursor, sort_key: &str) -> bool {
    match sort_key {
        "status" | "error_count" => cursor.value.parse::<i32>().is_ok(),
        "risk" => cursor
            .value
            .parse::<f64>()
            .is_ok_and(|value| value.is_finite()),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_proxy_list_where, decode_proxy_list_cursor, encode_proxy_list_cursor,
        proxy_definition_hash, Database,
        ProxyListCursor, ProxyListQuery, ProxyQuality, ProxyRow, ProxyValidationOutcome,
        Subscription,
    };
    use postgres::types::ToSql;

    #[test]
    fn proxy_list_excludes_internal_orphaned_rows() {
        let query = ProxyListQuery::default();
        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();

        let clause = build_proxy_list_where(&query, &mut params);

        assert_eq!(clause, "WHERE p.orphaned_at IS NULL");
        assert!(params.is_empty());
    }

    #[test]
    fn proxy_list_filters_by_subscription_source() {
        let query = ProxyListQuery {
            subscription_id: Some("sub-source-1".to_string()),
            ..Default::default()
        };
        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();

        let clause = build_proxy_list_where(&query, &mut params);

        assert_eq!(
            clause,
            "WHERE p.orphaned_at IS NULL AND p.subscription_id = $1"
        );
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn unique_exit_filter_uses_one_window_ranking_pass() {
        let query = ProxyListQuery {
            unique_exit_ip: true,
            ..Default::default()
        };
        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();

        let clause = build_proxy_list_where(&query, &mut params);

        assert!(clause.contains("ROW_NUMBER() OVER"));
        assert!(clause.contains("PARTITION BY quality.ip_address"));
        assert!(!clause.contains("NOT EXISTS"));
        assert!(params.is_empty());
    }

    #[test]
    fn proxy_list_cursor_round_trips_opaque_values() {
        let cursor = ProxyListCursor {
            sort: "name".to_string(),
            dir: "ASC".to_string(),
            value: "节点/東京 + 1".to_string(),
            id: "proxy-123".to_string(),
        };

        let encoded = encode_proxy_list_cursor(&cursor).expect("cursor should encode");
        let decoded = decode_proxy_list_cursor(&encoded).expect("cursor should decode");

        assert_eq!(decoded.sort, cursor.sort);
        assert_eq!(decoded.dir, cursor.dir);
        assert_eq!(decoded.value, cursor.value);
        assert_eq!(decoded.id, cursor.id);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn descending_cursor_uses_descending_id_tiebreaker() {
        let cursor = ProxyListCursor {
            sort: "name".to_string(),
            dir: "DESC".to_string(),
            value: "same-name".to_string(),
            id: "proxy-2".to_string(),
        };
        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();

        let next =
            super::build_proxy_cursor_clause(&cursor, "p.name", "name", "DESC", false, &mut params);
        assert!(next.contains("p.id < $2"));

        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();
        let previous =
            super::build_proxy_cursor_clause(&cursor, "p.name", "name", "DESC", true, &mut params);
        assert!(previous.contains("p.id > $2"));
    }

    #[test]
    fn definition_hash_ignores_display_tag_and_server_case() {
        let make = |id: &str, server: &str, password: &str| ProxyRow {
            id: id.into(),
            subscription_id: "sub".into(),
            name: id.into(),
            proxy_type: "trojan".into(),
            server: server.into(),
            port: 443,
            config_json: serde_json::json!({
                "type": "trojan",
                "tag": id,
                "server": server,
                "server_port": 443,
                "password": password
            })
            .to_string(),
            is_valid: false,
            local_port: None,
            error_count: 0,
            last_error: None,
            last_validated: None,
            created_at: String::new(),
            updated_at: String::new(),
            orphaned_at: None,
        };
        let first = make("first", "Example.COM", "secret");
        let equivalent = make("second", "example.com", "secret");
        let different = make("third", "example.com", "other");

        assert_eq!(
            proxy_definition_hash(&first),
            proxy_definition_hash(&equivalent)
        );
        assert_ne!(
            proxy_definition_hash(&first),
            proxy_definition_hash(&different)
        );
    }

    #[test]
    #[ignore = "requires ZENPROXY_TEST_DATABASE_URL pointing at a disposable PostgreSQL database"]
    fn postgres_migration_and_batch_paths_execute() {
        let url = std::env::var("ZENPROXY_TEST_DATABASE_URL")
            .expect("ZENPROXY_TEST_DATABASE_URL is required for this ignored test");
        let db = Database::new(&url, 4, std::time::Duration::from_secs(2)).unwrap();
        let normalized_url_is_unique: bool = db
            .with_conn(|conn| {
                Ok(conn
                    .query_one(
                        "SELECT index.indisunique
                         FROM pg_index index
                         WHERE index.indexrelid =
                               'idx_subscriptions_normalized_url'::regclass",
                        &[],
                    )?
                    .get(0))
            })
            .unwrap();
        assert!(normalized_url_is_unique);
        db.with_conn(|conn| {
            conn.execute("DELETE FROM subscriptions WHERE id LIKE 'test-sub-%'", &[])?;
            conn.execute(
                "DELETE FROM proxy_definitions definition
                 WHERE NOT EXISTS (
                    SELECT 1 FROM subscription_proxies membership
                    WHERE membership.definition_id = definition.id
                 )",
                &[],
            )?;
            conn.execute("DELETE FROM quality_check_leases", &[])?;
            Ok(())
        })
        .unwrap();
        let suffix = uuid::Uuid::new_v4().to_string();
        let first_sub_id = format!("test-sub-a-{suffix}");
        let second_sub_id = format!("test-sub-b-{suffix}");
        let first_id = format!("test-proxy-a-{suffix}");
        let second_id = format!("test-proxy-b-{suffix}");
        let third_id = format!("test-proxy-c-{suffix}");
        let fourth_id = format!("test-proxy-d-{suffix}");
        let fifth_id = format!("test-proxy-e-{suffix}");
        let sixth_id = format!("test-proxy-f-{suffix}");
        let seventh_id = format!("test-proxy-g-{suffix}");
        let eighth_id = format!("test-proxy-h-{suffix}");
        let legacy_upgrade_id = format!("test-proxy-legacy-{suffix}");
        let exit_ip = format!("2001:db8:{}:{}::1", &suffix[0..4], &suffix[4..8]);
        let now = chrono::Utc::now().to_rfc3339();
        let subscription = |id: &str, name: &str| Subscription {
            id: id.into(),
            name: name.into(),
            sub_type: "test".into(),
            url: None,
            content: Some("integration-test".into()),
            proxy_count: 1,
            raw_proxy_count: 1,
            duplicate_proxy_count: 0,
            refresh_interval_mins: None,
            last_refresh_at: Some(now.clone()),
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        let proxy = |id: &str, sub_id: &str, tag: &str| ProxyRow {
            id: id.into(),
            subscription_id: sub_id.into(),
            name: tag.into(),
            proxy_type: "trojan".into(),
            server: "Example.COM".into(),
            port: 443,
            config_json: serde_json::json!({
                "type": "trojan",
                "tag": tag,
                "server": "example.com",
                "server_port": 443,
                "password": format!("integration-secret-{suffix}")
            })
            .to_string(),
            is_valid: false,
            local_port: None,
            error_count: 0,
            last_error: None,
            last_validated: None,
            created_at: now.clone(),
            updated_at: now.clone(),
            orphaned_at: None,
        };

        db.insert_subscription_with_proxies_unless_url_exists(
            &subscription(&first_sub_id, "integration-a"),
            &[proxy(&first_id, &first_sub_id, "a")],
        )
        .unwrap();
        db.insert_subscription_with_proxies_unless_url_exists(
            &subscription(&second_sub_id, "integration-b"),
            &[proxy(&second_id, &second_sub_id, "b")],
        )
        .unwrap();
        let ordered_batch = db
            .get_proxy_records(&[
                second_id.clone(),
                format!("missing-{suffix}"),
                first_id.clone(),
            ])
            .unwrap();
        assert_eq!(
            ordered_batch
                .iter()
                .map(|(row, _)| row.id.as_str())
                .collect::<Vec<_>>(),
            vec![second_id.as_str(), first_id.as_str()]
        );
        let summary = db
            .get_subscription_summaries()
            .unwrap()
            .into_iter()
            .find(|subscription| subscription.id == first_sub_id)
            .unwrap();
        assert!(summary.content.is_none());
        assert_eq!(
            db.get_subscription(&first_sub_id)
                .unwrap()
                .unwrap()
                .content
                .as_deref(),
            Some("integration-test")
        );

        let first_claim = db
            .claim_due_validation_proxy_records(10, "integration-worker-a", 60)
            .unwrap();
        assert_eq!(first_claim.len(), 1, "exact copies share one health lease");
        assert!(db
            .claim_due_validation_proxy_records(10, "integration-worker-b", 60)
            .unwrap()
            .is_empty());
        let claimed_source_ids: Vec<_> = first_claim
            .iter()
            .map(|(row, _)| row.id.clone())
            .collect();
        assert_eq!(
            db.release_validation_leases(
                "integration-worker-a",
                &claimed_source_ids,
                0,
            )
            .unwrap(),
            1
        );
        let second_claim = db
            .claim_due_validation_proxy_records(10, "integration-worker-b", 60)
            .unwrap();
        assert_eq!(second_claim.len(), 1);

        db.sync_proxy_local_ports(&[(first_id.clone(), 12001)], &[])
            .unwrap();
        let applied = db
            .apply_validation_outcomes(
                &[ProxyValidationOutcome {
                    source_id: first_id.clone(),
                    is_valid: true,
                    error: None,
                    exit_ip: Some(exit_ip.clone()),
                    failure_kind: None,
                }],
                10,
            )
            .unwrap();
        assert_eq!(applied.len(), 2);
        assert!(applied.iter().all(|result| result.is_valid));
        let canonical_health_ok: bool = db
            .with_conn(|conn| {
                Ok(conn
                    .query_one(
                        "SELECT health.health_state = 'healthy'
                                AND health.lease_owner IS NULL
                                AND health.lease_until IS NULL
                         FROM proxy_health health
                         JOIN subscription_proxies membership
                           ON membership.definition_id = health.definition_id
                         WHERE membership.source_proxy_id = $1",
                        &[&first_id],
                    )?
                    .get(0))
            })
            .unwrap();
        assert!(canonical_health_ok);

        let quality_claim = db
            .claim_due_quality_proxy_records(
                10,
                &(chrono::Utc::now() - chrono::Duration::hours(72)).to_rfc3339(),
                3,
                2,
                "integration-quality-a",
                300,
            )
            .unwrap();
        assert_eq!(quality_claim.len(), 1, "same exit/definition is claimed once");
        assert!(db
            .claim_due_quality_proxy_records(
                10,
                &(chrono::Utc::now() - chrono::Duration::hours(72)).to_rfc3339(),
                3,
                2,
                "integration-quality-b",
                300,
            )
            .unwrap()
            .is_empty());
        assert_eq!(db.release_quality_leases("integration-quality-a").unwrap(), 1);

        // A different proxy definition can still resolve to the same physical
        // exit. Quality belongs to that observed exit and must fan out beyond
        // exact-definition duplicates.
        let mut third = proxy(&third_id, &second_sub_id, "c");
        third.config_json = serde_json::json!({
            "type": "trojan",
            "tag": "c",
            "server": "example.com",
            "server_port": 443,
            "password": format!("different-integration-secret-{suffix}")
        })
        .to_string();
        db.insert_proxies_batch(&[third]).unwrap();
        let third_validation = db
            .apply_validation_outcomes(
                &[ProxyValidationOutcome {
                    source_id: third_id.clone(),
                    is_valid: true,
                    error: None,
                    exit_ip: Some(exit_ip.clone()),
                    failure_kind: None,
                }],
                10,
            )
            .unwrap();
        assert_eq!(third_validation.len(), 1);

        let quality = ProxyQuality {
            proxy_id: first_id.clone(),
            ip_address: Some(exit_ip.clone()),
            country: Some("US".into()),
            ip_type: Some("Residential".into()),
            is_residential: true,
            chatgpt_accessible: true,
            google_accessible: true,
            risk_score: 0.1,
            risk_level: "Low".into(),
            extra_json: Some(
                serde_json::json!({
                    "schema_version": 2,
                    "incomplete_retry_count": 0,
                    "unlock": {
                        "google": {"status": "available"},
                        "chatgpt": {"status": "available"}
                    }
                })
                .to_string(),
            ),
            checked_at: now.clone(),
        };
        assert_eq!(db.apply_quality_outcomes(&[quality]).unwrap().len(), 3);
        let third_quality = db
            .with_conn(|conn| {
                conn.query_one(
                    "SELECT country, risk_level
                     FROM normalized_proxy_quality
                     WHERE proxy_id = $1",
                    &[&third_id],
                )
            })
            .unwrap();
        assert_eq!(third_quality.get::<_, Option<String>>(0).as_deref(), Some("US"));
        assert_eq!(third_quality.get::<_, String>(1), "Low");

        let mut fifth = proxy(&fifth_id, &first_sub_id, "e");
        fifth.server = "no-exit.example.com".into();
        fifth.config_json = serde_json::json!({
            "type": "trojan",
            "tag": "e",
            "server": "no-exit.example.com",
            "server_port": 443,
            "password": format!("no-exit-secret-{suffix}")
        })
        .to_string();
        db.insert_proxies_batch(&[fifth]).unwrap();
        db.apply_validation_outcomes(
            &[ProxyValidationOutcome {
                source_id: fifth_id.clone(),
                is_valid: true,
                error: Some("exit IP providers unavailable".into()),
                exit_ip: None,
                failure_kind: Some("exit_ip_unavailable".into()),
            }],
            10,
        )
        .unwrap();
        let measurement_only_failure: (String, i32, Option<String>) = db
            .with_conn(|conn| {
                let row = conn.query_one(
                    "SELECT health.health_state, health.consecutive_failures,
                            health.failure_kind
                     FROM proxy_health health
                     JOIN subscription_proxies membership
                       ON membership.definition_id = health.definition_id
                     WHERE membership.source_proxy_id = $1",
                    &[&fifth_id],
                )?;
                Ok((row.get(0), row.get(1), row.get(2)))
            })
            .unwrap();
        assert_eq!(
            measurement_only_failure,
            ("healthy".into(), 0, Some("exit_ip_unavailable".into()))
        );
        let no_exit_quality = ProxyQuality {
            proxy_id: fifth_id.clone(),
            ip_address: None,
            country: None,
            ip_type: None,
            is_residential: false,
            chatgpt_accessible: false,
            google_accessible: false,
            risk_score: 1.0,
            risk_level: "Unknown".into(),
            extra_json: Some(
                serde_json::json!({
                    "schema_version": 2,
                    "incomplete_retry_count": 2,
                    "next_retry_at": (chrono::Utc::now() + chrono::Duration::hours(1))
                        .to_rfc3339(),
                    "unlock": {
                        "google": {"status": "error"},
                        "chatgpt": {"status": "error"}
                    }
                })
                .to_string(),
            ),
            checked_at: now.clone(),
        };
        db.apply_quality_outcomes(&[no_exit_quality]).unwrap();
        let persisted_retry = db.get_quality(&fifth_id).unwrap().unwrap();
        assert!(persisted_retry.ip_address.is_none());
        assert!(persisted_retry
            .extra_json
            .as_deref()
            .is_some_and(|json| json.contains("incomplete_retry_count")));
        assert!(db
            .claim_due_quality_proxy_records(
                10,
                &(chrono::Utc::now() - chrono::Duration::hours(72)).to_rfc3339(),
                3,
                2,
                "integration-quality-retry",
                300,
            )
            .unwrap()
            .is_empty());

        let dirty_quality_counters = db
            .with_conn(|conn| {
                let mut tx = conn.transaction()?;
                tx.execute(
                    "UPDATE quality_retry_state retry
                     SET extra_json = jsonb_build_object(
                         'schema_version', 'legacy',
                         'incomplete_retry_count', '999999999999999999999'
                     )
                     FROM subscription_proxies membership
                     WHERE membership.source_proxy_id = $1
                       AND retry.definition_id = membership.definition_id",
                    &[&fifth_id],
                )?;
                let row = tx.query_one(
                    "SELECT schema_version, incomplete_retry_count
                     FROM normalized_proxy_quality
                     WHERE proxy_id = $1",
                    &[&fifth_id],
                )?;
                let counters = (row.get::<_, i32>(0), row.get::<_, i32>(1));
                tx.rollback()?;
                Ok(counters)
            })
            .unwrap();
        assert_eq!(dirty_quality_counters, (0, 0));

        let fourth = proxy(&fourth_id, &second_sub_id, "d");
        db.insert_proxies_batch(&[fourth]).unwrap();
        let inherited: (bool, Option<String>) = db
            .with_conn(|conn| {
                let row = conn.query_one(
                    "SELECT p.is_valid, q.country
                     FROM normalized_proxies p
                     LEFT JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                     WHERE p.id = $1",
                    &[&fourth_id],
                )?;
                Ok((row.get(0), row.get(1)))
            })
            .unwrap();
        assert_eq!(inherited, (true, Some("US".into())));

        let normalized_cardinality: (i64, i64, Option<i32>, Option<String>) = db
            .with_conn(|conn| {
                let row = conn.query_one(
                    "SELECT
                        (SELECT COUNT(*)
                         FROM proxy_health health
                         JOIN subscription_proxies membership
                           ON membership.definition_id = health.definition_id
                         WHERE membership.source_proxy_id = $1),
                        (SELECT COUNT(*) FROM exit_quality
                         WHERE ip_address = zenproxy_try_inet($2)),
                        (SELECT runtime.local_port
                         FROM proxy_runtime runtime
                         JOIN subscription_proxies membership
                           ON membership.definition_id = runtime.definition_id
                         WHERE membership.source_proxy_id = $1),
                        (SELECT runtime.binding_owner_id
                         FROM proxy_runtime runtime
                         JOIN subscription_proxies membership
                           ON membership.definition_id = runtime.definition_id
                         WHERE membership.source_proxy_id = $1)",
                    &[&first_id, &exit_ip],
                )?;
                Ok((row.get(0), row.get(1), row.get(2), row.get(3)))
            })
            .unwrap();
        assert_eq!(
            normalized_cardinality,
            (1, 1, Some(12001), Some(first_id.clone()))
        );
        assert_eq!(
            db.get_proxy_binding_owner(&fourth_id).unwrap().as_deref(),
            Some(first_id.as_str())
        );
        assert_eq!(
            db.get_proxy_record(&fourth_id)
                .unwrap()
                .unwrap()
                .0
                .local_port,
            Some(12001),
            "runtime binding is shared by exact definitions"
        );
        let selectable_test_rows: Vec<_> = db
            .get_selectable_proxy_records()
            .unwrap()
            .into_iter()
            .filter(|(row, _)| row.id.ends_with(&suffix))
            .collect();
        assert_eq!(
            selectable_test_rows.len(),
            2,
            "the data-plane snapshot keeps one membership per definition"
        );

        // Contract proof: legacy copies may be absent or stale without
        // changing any authoritative read. The normalization sync triggers
        // must already be gone when Database::new returns.
        db.with_conn(|conn| {
            conn.execute(
                "INSERT INTO proxies (
                    id, subscription_id, name, proxy_type, server, port,
                    config_json, definition_hash, is_valid, local_port,
                    error_count, last_error, last_validated,
                    created_at, updated_at, orphaned_at
                 )
                 SELECT id, subscription_id, 'stale legacy name', proxy_type,
                        server, port, config_json, definition_hash,
                        FALSE, NULL, 99, 'stale legacy error', NULL,
                        created_at, updated_at, orphaned_at
                 FROM normalized_proxies WHERE id = $1
                 ON CONFLICT (id) DO UPDATE SET
                    is_valid = FALSE, local_port = NULL, error_count = 99,
                    last_error = 'stale legacy error'",
                &[&first_id],
            )?;
            conn.execute(
                "INSERT INTO proxy_quality (
                    proxy_id, ip_address, country, ip_type, is_residential,
                    chatgpt_accessible, google_accessible, risk_score,
                    risk_level, extra_json, checked_at
                 ) VALUES (
                    $1, '198.51.100.250', 'ZZ', 'Datacenter', FALSE,
                    FALSE, FALSE, 1.0, 'High', '{}', $2
                 )
                 ON CONFLICT (proxy_id) DO UPDATE SET
                    ip_address = EXCLUDED.ip_address,
                    country = EXCLUDED.country,
                    risk_level = EXCLUDED.risk_level",
                &[&first_id, &now],
            )?;
            // Recreate the pre-normalization column contract in this
            // disposable database. Production databases upgrading from that
            // version have no NOT NULL constraint until cutover completes.
            conn.batch_execute(
                "ALTER TABLE proxies ALTER COLUMN definition_hash DROP NOT NULL",
            )?;
            conn.execute(
                "INSERT INTO proxies (
                    id, subscription_id, name, proxy_type, server, port,
                    config_json, definition_hash, is_valid, local_port,
                    error_count, last_error, last_validated,
                    created_at, updated_at, orphaned_at
                 ) VALUES (
                    $1, $2, 'legacy upgrade row', 'trojan', $3, 443,
                    $4, NULL, TRUE, NULL, 0, NULL, $5, $5, $5, NULL
                 )",
                &[
                    &legacy_upgrade_id,
                    &first_sub_id,
                    &format!("legacy-{suffix}.example.com"),
                    &serde_json::json!({
                        "type": "trojan",
                        "tag": "legacy upgrade row",
                        "server": format!("legacy-{suffix}.example.com"),
                        "server_port": 443,
                        "password": "legacy-secret"
                    })
                    .to_string(),
                    &now,
                ],
            )?;
            let sync_triggers: i64 = conn
                .query_one(
                    "SELECT COUNT(*) FROM pg_trigger
                     WHERE NOT tgisinternal
                       AND tgname IN (
                           'trg_zenproxy_sync_normalized_proxy',
                           'trg_zenproxy_delete_normalized_membership',
                           'trg_zenproxy_sync_normalized_health',
                           'trg_zenproxy_sync_exit_quality',
                           'trg_zenproxy_sync_normalized_runtime'
                       )",
                    &[],
                )?
                .get(0);
            assert_eq!(sync_triggers, 0);
            Ok(())
        })
        .unwrap();
        let authoritative = db.get_proxy_record(&first_id).unwrap().unwrap();
        assert!(authoritative.0.is_valid);
        assert_eq!(authoritative.0.local_port, Some(12001));
        assert_eq!(authoritative.1.unwrap().country.as_deref(), Some("US"));
        assert!(
            db.get_proxy_record(&legacy_upgrade_id).unwrap().is_none(),
            "a legacy row with no definition hash is not authoritative before restart"
        );
        let reopened = Database::new(&url, 2, std::time::Duration::from_secs(2)).unwrap();
        let after_restart = reopened.get_proxy_record(&first_id).unwrap().unwrap();
        assert!(after_restart.0.is_valid);
        assert_eq!(after_restart.0.local_port, Some(12001));
        assert_eq!(after_restart.1.unwrap().country.as_deref(), Some("US"));
        let upgraded_legacy = reopened
            .get_proxy_record(&legacy_upgrade_id)
            .unwrap()
            .expect("legacy PostgreSQL rows must be normalized during an in-place upgrade");
        assert!(upgraded_legacy.0.is_valid);
        assert_eq!(upgraded_legacy.0.server, format!("legacy-{suffix}.example.com"));
        drop(reopened);

        let make_distinct = |id: &str, host: &str| {
            let mut row = proxy(id, &first_sub_id, id);
            row.server = host.to_string();
            row.config_json = serde_json::json!({
                "type": "trojan",
                "tag": id,
                "server": host,
                "server_port": 443,
                "password": format!("{id}-secret")
            })
            .to_string();
            row
        };
        db.insert_proxies_batch(&[
            make_distinct(&sixth_id, "lease-a.example.com"),
            make_distinct(&seventh_id, "lease-b.example.com"),
        ])
        .unwrap();
        db.apply_validation_outcomes(
            &[
                ProxyValidationOutcome {
                    source_id: sixth_id.clone(),
                    is_valid: true,
                    error: None,
                    exit_ip: Some("198.51.100.61".into()),
                    failure_kind: None,
                },
                ProxyValidationOutcome {
                    source_id: seventh_id.clone(),
                    is_valid: true,
                    error: None,
                    exit_ip: Some("198.51.100.62".into()),
                    failure_kind: None,
                },
            ],
            10,
        )
        .unwrap();
        let lease_limit_first = db
            .claim_due_quality_proxy_records(
                1,
                &(chrono::Utc::now() - chrono::Duration::hours(72)).to_rfc3339(),
                3,
                2,
                "quality-limit-a",
                300,
            )
            .unwrap();
        let lease_limit_second = db
            .claim_due_quality_proxy_records(
                1,
                &(chrono::Utc::now() - chrono::Duration::hours(72)).to_rfc3339(),
                3,
                2,
                "quality-limit-b",
                300,
            )
            .unwrap();
        assert_eq!(lease_limit_first.len(), 1);
        assert_eq!(lease_limit_second.len(), 1);
        assert_ne!(lease_limit_first[0].0.id, lease_limit_second[0].0.id);
        let same_owner_followup = db
            .claim_due_quality_proxy_records(
                100,
                &(chrono::Utc::now() - chrono::Duration::hours(72)).to_rfc3339(),
                3,
                2,
                "quality-limit-a",
                300,
            )
            .unwrap();
        assert!(
            same_owner_followup
                .iter()
                .all(|record| record.0.id != lease_limit_first[0].0.id),
            "a worker must not reclaim its own still-active quality lease"
        );
        db.release_quality_leases("quality-limit-a").unwrap();
        db.release_quality_leases("quality-limit-b").unwrap();

        let mut refresh_before = make_distinct(&eighth_id, "refresh.example.com");
        refresh_before.config_json = serde_json::json!({
            "type": "trojan",
            "tag": &eighth_id,
            "server": "refresh.example.com",
            "server_port": 443,
            "password": "before-refresh"
        })
        .to_string();
        db.insert_proxies_batch(std::slice::from_ref(&refresh_before))
            .unwrap();
        db.apply_validation_outcomes(
            &[ProxyValidationOutcome {
                source_id: eighth_id.clone(),
                is_valid: true,
                error: None,
                exit_ip: None,
                failure_kind: None,
            }],
            10,
        )
        .unwrap();
        let old_refresh_definition: String = db
            .with_conn(|conn| {
                Ok(conn
                    .query_one(
                        "SELECT definition_id FROM subscription_proxies
                         WHERE source_proxy_id = $1",
                        &[&eighth_id],
                    )?
                    .get(0))
            })
            .unwrap();
        let mut refresh_after = refresh_before;
        refresh_after.config_json = serde_json::json!({
            "type": "trojan",
            "tag": &eighth_id,
            "server": "refresh.example.com",
            "server_port": 443,
            "password": "after-refresh"
        })
        .to_string();
        refresh_after.is_valid = false;
        refresh_after.error_count = 0;
        refresh_after.last_error = None;
        refresh_after.last_validated = None;
        db.insert_proxies_batch(std::slice::from_ref(&refresh_after))
            .unwrap();
        let refreshed = db.get_proxy_record(&eighth_id).unwrap().unwrap().0;
        assert!(!refreshed.is_valid);
        assert!(refreshed.last_validated.is_none());
        let refresh_definition_state: (String, i64) = db
            .with_conn(|conn| {
                let current: String = conn
                    .query_one(
                        "SELECT definition_id FROM subscription_proxies
                         WHERE source_proxy_id = $1",
                        &[&eighth_id],
                    )?
                    .get(0);
                let old_count: i64 = conn
                    .query_one(
                        "SELECT COUNT(*) FROM proxy_definitions WHERE id = $1",
                        &[&old_refresh_definition],
                    )?
                    .get(0);
                Ok((current, old_count))
            })
            .unwrap();
        assert_ne!(refresh_definition_state.0, old_refresh_definition);
        assert_eq!(refresh_definition_state.1, 0);

        let unique_page = db
            .list_proxy_page(&ProxyListQuery {
                page: 1,
                page_size: 20,
                unique_exit_ip: true,
                subscription_id: Some(second_sub_id.clone()),
                ..ProxyListQuery::default()
            })
            .unwrap();
        assert_eq!(unique_page.filtered, 1);
        assert_eq!(unique_page.proxies.len(), 1);
        db.mark_proxy_relay_failed(&third_id, "integration relay failure", 1)
            .unwrap();
        let relay_failure_state: (String, Option<String>) = db
            .with_conn(|conn| {
                let row = conn.query_one(
                    "SELECT health.health_state, health.failure_kind
                     FROM proxy_health health
                     JOIN subscription_proxies membership
                       ON membership.definition_id = health.definition_id
                     WHERE membership.source_proxy_id = $1",
                    &[&third_id],
                )?;
                Ok((row.get(0), row.get(1)))
            })
            .unwrap();
        assert_eq!(
            relay_failure_state,
            ("unhealthy".into(), Some("relay_failure".into()))
        );

        let (_, overlaps) = db.get_subscription_duplicate_overview().unwrap();
        assert!(overlaps.iter().any(|edge| {
            edge.left_subscription_id == first_sub_id
                && edge.right_subscription_id == second_sub_id
                && edge.shared_exact_nodes == 1
        }));
        let typed_materialization_ok: bool = db
            .with_conn(|conn| {
                Ok(conn
                    .query_one(
                        "SELECT definition_hash IS NOT NULL
                                AND updated_at_ts IS NOT NULL
                                AND q.checked_at_ts IS NOT NULL
                                AND q.extra_jsonb IS NOT NULL
                                AND q.schema_version = 2
                         FROM normalized_proxies p
                         JOIN normalized_proxy_quality q ON q.proxy_id = p.id
                         WHERE p.id = $1",
                        &[&first_id],
                    )?
                    .get(0))
            })
            .unwrap();
        assert!(typed_materialization_ok);
        let stats = db.get_stats().unwrap();
        let integrity = &stats["normalization_integrity"];
        for field in ["health_missing", "runtime_missing", "unreferenced_definitions"] {
            assert_eq!(integrity[field].as_i64(), Some(0), "integrity field {field}");
        }

        for expected in 1..=3 {
            assert_eq!(
                db.record_proxy_binding_failures(std::slice::from_ref(&sixth_id))
                    .unwrap(),
                vec![(sixth_id.clone(), expected)]
            );
        }
        let binding_failure_state: (i32, Option<String>, bool) = db
            .with_conn(|conn| {
                let row = conn.query_one(
                    "SELECT runtime.binding_failure_count, health.failure_kind,
                            health.lease_owner IS NULL AND health.lease_until IS NULL
                     FROM subscription_proxies membership
                     JOIN proxy_runtime runtime
                       ON runtime.definition_id = membership.definition_id
                     JOIN proxy_health health
                       ON health.definition_id = membership.definition_id
                     WHERE membership.source_proxy_id = $1",
                    &[&sixth_id],
                )?;
                Ok((row.get(0), row.get(1), row.get(2)))
            })
            .unwrap();
        assert_eq!(
            binding_failure_state,
            (3, Some("binding_unavailable".into()), true)
        );
        assert!(
            db.get_proxy_record(&sixth_id).unwrap().is_some(),
            "local binding failures must not delete subscription inventory"
        );
        db.update_proxy_local_port(&sixth_id, 12002).unwrap();
        let recovered_binding_state: (i32, Option<String>) = db
            .with_conn(|conn| {
                let row = conn.query_one(
                    "SELECT runtime.binding_failure_count, health.failure_kind
                     FROM subscription_proxies membership
                     JOIN proxy_runtime runtime
                       ON runtime.definition_id = membership.definition_id
                     JOIN proxy_health health
                       ON health.definition_id = membership.definition_id
                     WHERE membership.source_proxy_id = $1",
                    &[&sixth_id],
                )?;
                Ok((row.get(0), row.get(1)))
            })
            .unwrap();
        assert_eq!(recovered_binding_state, (0, None));

        db.mark_proxy_orphaned(&first_id, &now).unwrap();
        let deleted = db
            .apply_validation_outcomes(
                &[ProxyValidationOutcome {
                    source_id: first_id.clone(),
                    is_valid: false,
                    error: Some("integration failure".into()),
                    exit_ip: None,
                    failure_kind: Some("probe_failure".into()),
                }],
                1,
            )
            .unwrap();
        assert!(deleted
            .iter()
            .any(|result| result.proxy_id == first_id && result.deleted_orphan));
        assert!(db.get_proxy_record(&first_id).unwrap().is_none());
        assert!(db.get_proxy_record(&second_id).unwrap().is_some());
        let failure_state: (String, Option<String>) = db
            .with_conn(|conn| {
                let row = conn.query_one(
                    "SELECT health.health_state, health.failure_kind
                     FROM proxy_health health
                     JOIN subscription_proxies membership
                       ON membership.definition_id = health.definition_id
                     WHERE membership.source_proxy_id = $1",
                    &[&second_id],
                )?;
                Ok((row.get(0), row.get(1)))
            })
            .unwrap();
        assert_eq!(failure_state, ("unhealthy".into(), Some("probe_failure".into())));

        db.delete_subscription(&first_sub_id).unwrap();
        db.delete_subscription(&second_sub_id).unwrap();
    }
}
