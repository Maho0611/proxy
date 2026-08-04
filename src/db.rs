use base64::Engine;
use postgres::types::ToSql;
use postgres::{Client, Config, NoTls, Row};
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Client>,
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
    pub fn new(url: &str) -> Result<Self, postgres::Error> {
        let mut config: Config = url.parse()?;
        config.application_name("zenproxy");
        let conn = tokio::task::block_in_place(|| config.connect(NoTls))?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    fn with_conn<T>(
        &self,
        f: impl FnOnce(&mut Client) -> Result<T, postgres::Error>,
    ) -> Result<T, postgres::Error> {
        tokio::task::block_in_place(|| {
            let mut conn = self.conn.lock().unwrap();
            f(&mut conn)
        })
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
                ALTER TABLE proxies ADD COLUMN IF NOT EXISTS binding_failure_count INTEGER NOT NULL DEFAULT 0;
                ALTER TABLE proxies ADD COLUMN IF NOT EXISTS last_binding_failure TEXT;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS refresh_interval_mins INTEGER;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS last_refresh_at TEXT;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS raw_proxy_count INTEGER NOT NULL DEFAULT 0;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS duplicate_proxy_count INTEGER NOT NULL DEFAULT 0;

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
                ",
            )?;
            Ok(())
        })
    }

    pub fn insert_subscription(&self, sub: &Subscription) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
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
            Ok(())
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
            conn.execute(
                "DELETE FROM proxy_quality WHERE proxy_id IN (
                    SELECT id FROM proxies WHERE subscription_id = $1
                 )",
                &[&id],
            )?;
            conn.execute("DELETE FROM proxies WHERE subscription_id = $1", &[&id])?;
            conn.execute("DELETE FROM subscriptions WHERE id = $1", &[&id])?;
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
            conn.execute(
                "INSERT INTO proxies (
                    id, subscription_id, name, proxy_type, server, port, config_json,
                    is_valid, local_port, error_count, last_error, last_validated, created_at, updated_at, orphaned_at
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7,
                    $8, $9, $10, $11, $12, $13, $14, $15
                 )
                 ON CONFLICT (id) DO UPDATE SET
                    subscription_id = EXCLUDED.subscription_id,
                    name = EXCLUDED.name,
                    proxy_type = EXCLUDED.proxy_type,
                    server = EXCLUDED.server,
                    port = EXCLUDED.port,
                    config_json = EXCLUDED.config_json,
                    is_valid = EXCLUDED.is_valid,
                    local_port = EXCLUDED.local_port,
                    error_count = EXCLUDED.error_count,
                    last_error = EXCLUDED.last_error,
                    last_validated = EXCLUDED.last_validated,
                    created_at = EXCLUDED.created_at,
                    updated_at = EXCLUDED.updated_at,
                    orphaned_at = EXCLUDED.orphaned_at",
                &[
                    &proxy.id,
                    &proxy.subscription_id,
                    &proxy.name,
                    &proxy.proxy_type,
                    &proxy.server,
                    &proxy.port,
                    &proxy.config_json,
                    &proxy.is_valid,
                    &proxy.local_port,
                    &proxy.error_count,
                    &proxy.last_error,
                    &proxy.last_validated,
                    &proxy.created_at,
                    &proxy.updated_at,
                    &proxy.orphaned_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn insert_proxies_batch(&self, proxies: &[ProxyRow]) -> Result<(), postgres::Error> {
        if proxies.is_empty() {
            return Ok(());
        }

        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            let stmt = tx.prepare(
                "INSERT INTO proxies (
                    id, subscription_id, name, proxy_type, server, port, config_json,
                    is_valid, local_port, error_count, last_error, last_validated, created_at, updated_at, orphaned_at
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7,
                    $8, $9, $10, $11, $12, $13, $14, $15
                 )
                 ON CONFLICT (id) DO UPDATE SET
                    subscription_id = EXCLUDED.subscription_id,
                    name = EXCLUDED.name,
                    proxy_type = EXCLUDED.proxy_type,
                    server = EXCLUDED.server,
                    port = EXCLUDED.port,
                    config_json = EXCLUDED.config_json,
                    is_valid = EXCLUDED.is_valid,
                    local_port = EXCLUDED.local_port,
                    error_count = EXCLUDED.error_count,
                    last_error = EXCLUDED.last_error,
                    last_validated = EXCLUDED.last_validated,
                    created_at = EXCLUDED.created_at,
                    updated_at = EXCLUDED.updated_at,
                    orphaned_at = EXCLUDED.orphaned_at",
            )?;

            for proxy in proxies {
                tx.execute(
                    &stmt,
                    &[
                        &proxy.id,
                        &proxy.subscription_id,
                        &proxy.name,
                        &proxy.proxy_type,
                        &proxy.server,
                        &proxy.port,
                        &proxy.config_json,
                        &proxy.is_valid,
                        &proxy.local_port,
                        &proxy.error_count,
                        &proxy.last_error,
                        &proxy.last_validated,
                        &proxy.created_at,
                        &proxy.updated_at,
                        &proxy.orphaned_at,
                    ],
                )?;
            }

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
                 FROM proxies ORDER BY created_at DESC",
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
                 LEFT JOIN proxies p
                   ON p.subscription_id = s.id AND p.orphaned_at IS NULL
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
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

            let exact_rows = conn.query(
                "SELECT id, subscription_id, name, proxy_type, server, port, config_json,
                        is_valid, local_port, error_count, last_error, last_validated,
                        created_at, updated_at, orphaned_at
                 FROM proxies WHERE orphaned_at IS NULL",
                &[],
            )?;
            let mut exact_sources: std::collections::HashMap<
                String,
                std::collections::HashSet<String>,
            > = std::collections::HashMap::new();
            for row in &exact_rows {
                let proxy = proxy_from_row(row);
                exact_sources
                    .entry(crate::api::subscription::proxy_row_definition_key(&proxy))
                    .or_default()
                    .insert(proxy.subscription_id);
            }
            let mut exact_overlaps: std::collections::HashMap<(String, String), i64> =
                std::collections::HashMap::new();
            for sources in exact_sources.values() {
                let mut sources: Vec<_> = sources.iter().cloned().collect();
                sources.sort_unstable();
                for left_index in 0..sources.len() {
                    for right_index in (left_index + 1)..sources.len() {
                        *exact_overlaps
                            .entry((sources[left_index].clone(), sources[right_index].clone()))
                            .or_default() += 1;
                    }
                }
            }

            let overlap_rows = conn.query(
                "WITH endpoint_sources AS (
                    SELECT DISTINCT subscription_id, LOWER(server) AS server, port, proxy_type
                    FROM proxies
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
                 ), exit_sources AS (
                    SELECT DISTINCT p.subscription_id, q.ip_address
                    FROM proxies p
                    JOIN proxy_quality q ON q.proxy_id = p.id
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
                 )
                 SELECT COALESCE(e.left_id, x.left_id) AS left_id,
                        COALESCE(e.right_id, x.right_id) AS right_id,
                        COALESCE(e.shared_endpoints, 0) AS shared_endpoints,
                        COALESCE(x.shared_exit_ips, 0) AS shared_exit_ips
                 FROM endpoint_overlap e
                 FULL OUTER JOIN exit_overlap x
                   ON x.left_id = e.left_id AND x.right_id = e.right_id
                 ORDER BY (COALESCE(e.shared_endpoints, 0) + COALESCE(x.shared_exit_ips, 0)) DESC,
                          left_id, right_id",
                &[],
            )?;
            let overlaps = overlap_rows
                .iter()
                .map(|row| {
                    let left_subscription_id: String = row.get("left_id");
                    let right_subscription_id: String = row.get("right_id");
                    SubscriptionOverlap {
                        shared_exact_nodes: exact_overlaps
                            .get(&(left_subscription_id.clone(), right_subscription_id.clone()))
                            .copied()
                            .unwrap_or(0),
                        left_subscription_id,
                        right_subscription_id,
                        shared_endpoints: row.get("shared_endpoints"),
                        shared_exit_ips: row.get("shared_exit_ips"),
                    }
                })
                .collect::<Vec<_>>();
            let mut overlaps_by_pair: std::collections::HashMap<_, _> = overlaps
                .into_iter()
                .map(|overlap| {
                    (
                        (
                            overlap.left_subscription_id.clone(),
                            overlap.right_subscription_id.clone(),
                        ),
                        overlap,
                    )
                })
                .collect();
            for ((left_subscription_id, right_subscription_id), shared_exact_nodes) in
                exact_overlaps
            {
                overlaps_by_pair
                    .entry((left_subscription_id.clone(), right_subscription_id.clone()))
                    .or_insert(SubscriptionOverlap {
                        left_subscription_id,
                        right_subscription_id,
                        shared_exact_nodes,
                        shared_endpoints: 0,
                        shared_exit_ips: 0,
                    });
            }
            let mut overlaps: Vec<_> = overlaps_by_pair.into_values().collect();
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
                        FROM proxies p
                        JOIN proxy_quality q ON q.proxy_id = p.id
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
                        FROM proxies p
                        JOIN proxy_quality q ON q.proxy_id = p.id
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
                 FROM proxies p
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                 WHERE p.id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(proxy_record_from_join_row))
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
                    FROM proxies p
                    JOIN proxy_quality q ON q.proxy_id = p.id
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

    pub fn get_random_valid_proxy_records(
        &self,
        filter: &crate::pool::manager::ProxyFilter,
        limit: usize,
        recent_error_before: Option<&str>,
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        let limit = limit.max(1) as i64;
        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();
        let where_clause = build_fetch_proxy_where(filter, &mut params, true);
        let order_by_clause = build_random_valid_proxy_order_by(&mut params, recent_error_before);
        params.push(Box::new(limit));
        let limit_idx = params.len();

        self.with_conn(|conn| {
            let param_refs: Vec<&(dyn ToSql + Sync)> =
                params.iter().map(|p| &**p as &(dyn ToSql + Sync)).collect();
            let sql = format!(
                "SELECT
                    p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port, p.config_json,
                    p.is_valid, p.local_port, p.error_count, p.last_error, p.last_validated,
                    p.created_at, p.updated_at, p.orphaned_at,
                    p.proxy_id, p.ip_address, p.country, p.ip_type, p.is_residential,
                    p.chatgpt_accessible, p.google_accessible, p.risk_score, p.risk_level,
                    p.extra_json, p.checked_at
                 FROM (
                    SELECT DISTINCT ON (q.ip_address)
                        p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port,
                        p.config_json, p.is_valid, p.local_port, p.error_count, p.last_error,
                        p.last_validated, p.created_at, p.updated_at, p.orphaned_at,
                        q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                        q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                        q.extra_json, q.checked_at
                    FROM proxies p
                    JOIN proxy_quality q ON q.proxy_id = p.id
                    {where_clause}
                    ORDER BY q.ip_address, p.error_count ASC,
                             p.last_validated DESC NULLS LAST, p.updated_at DESC, p.id ASC
                 ) p
                 ORDER BY {order_by_clause}
                 LIMIT ${limit_idx}"
            );
            let rows = conn.query(&sql, &param_refs)?;
            Ok(rows.iter().map(proxy_record_from_join_row).collect())
        })
    }

    pub fn get_due_quality_proxy_records(
        &self,
        limit: usize,
        stale_before: &str,
        max_incomplete_retries: u8,
        quality_schema_version: u8,
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        let limit = limit.max(1) as i64;
        let max_incomplete_retries = max_incomplete_retries as i32;
        let quality_schema_version = quality_schema_version as i32;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT
                    p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port, p.config_json,
                    p.is_valid, p.local_port, p.error_count, p.last_error, p.last_validated,
                    p.created_at, p.updated_at, p.orphaned_at,
                    q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                    q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                    q.extra_json, q.checked_at
                 FROM proxies p
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                 WHERE p.is_valid = TRUE
                   AND p.orphaned_at IS NULL
                   AND (
                        q.proxy_id IS NULL
                        OR q.checked_at <= $1
                        OR COALESCE((q.extra_json::jsonb ->> 'schema_version')::int, 0) < $3
                        OR (
                            (q.country IS NULL OR q.ip_type IS NULL OR q.ip_address IS NULL OR q.risk_level = 'Unknown')
                            AND COALESCE((q.extra_json::jsonb ->> 'incomplete_retry_count')::int, 0) < $2
                        )
                   )
                 ORDER BY
                    CASE WHEN p.local_port IS NULL THEN 1 ELSE 0 END ASC,
                    q.checked_at ASC NULLS FIRST,
                    p.last_validated DESC NULLS LAST,
                    p.updated_at DESC
                 LIMIT $4",
                &[
                    &stale_before,
                    &max_incomplete_retries,
                    &quality_schema_version,
                    &limit,
                ],
            )?;
            Ok(rows.iter().map(proxy_record_from_join_row).collect())
        })
    }

    pub fn get_untested_proxy_records(
        &self,
        limit: usize,
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        let limit = limit as i64;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT
                    p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port, p.config_json,
                    p.is_valid, p.local_port, p.error_count, p.last_error, p.last_validated,
                    p.created_at, p.updated_at, p.orphaned_at,
                    q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                    q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                    q.extra_json, q.checked_at
                 FROM proxies p
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                 WHERE p.is_valid = FALSE
                   AND p.last_validated IS NULL
                   AND p.orphaned_at IS NULL
                 ORDER BY
                    CASE WHEN p.error_count > 0 THEN 0 ELSE 1 END ASC,
                    p.error_count DESC,
                    p.created_at ASC
                 LIMIT $1",
                &[&limit],
            )?;
            Ok(rows.iter().map(proxy_record_from_join_row).collect())
        })
    }

    pub fn get_valid_with_errors_ids(
        &self,
        min_error_count: u32,
    ) -> Result<Vec<String>, postgres::Error> {
        let min_error_count = min_error_count as i32;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id
                 FROM proxies
                 WHERE is_valid = TRUE AND error_count >= $1
                 ORDER BY error_count DESC, updated_at DESC",
                &[&min_error_count],
            )?;
            Ok(rows.iter().map(|row| row.get::<_, String>(0)).collect())
        })
    }

    /// Return a fair validation batch made from independent cohorts. Keeping the
    /// cohorts separate prevents a large stream of new subscriptions from
    /// starving valid rechecks or cooled-down invalid retries.
    pub fn get_validation_proxy_records(
        &self,
        new_limit: usize,
        valid_limit: usize,
        invalid_limit: usize,
        valid_before: &str,
        retry_before: &str,
        orphaned_before: &str,
        error_threshold: u32,
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        let columns =
            "p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port, p.config_json,
                       p.is_valid, p.local_port, p.error_count, p.last_error, p.last_validated,
                       p.created_at, p.updated_at, p.orphaned_at,
                       q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                       q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                       q.extra_json, q.checked_at";
        let new_limit = new_limit as i64;
        let valid_limit = valid_limit as i64;
        let invalid_limit = invalid_limit as i64;
        let error_threshold = error_threshold as i32;

        self.with_conn(|conn| {
            let mut records = Vec::with_capacity(
                new_limit.max(0) as usize
                    + valid_limit.max(0) as usize
                    + invalid_limit.max(0) as usize,
            );

            if new_limit > 0 {
                let sql = format!(
                    "SELECT {columns}
                     FROM proxies p
                     LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                     WHERE p.is_valid = FALSE
                       AND p.last_validated IS NULL
                       AND p.error_count = 0
                       AND p.orphaned_at IS NULL
                       AND (p.last_binding_failure IS NULL OR p.last_binding_failure <= $1)
                     ORDER BY p.created_at ASC, p.id ASC
                     LIMIT $2"
                );
                records.extend(
                    conn.query(&sql, &[&retry_before, &new_limit])?
                        .iter()
                        .map(proxy_record_from_join_row),
                );
            }

            if valid_limit > 0 {
                let sql = format!(
                    "SELECT {columns}
                     FROM proxies p
                     LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                     WHERE p.is_valid = TRUE
                       AND (
                            (p.orphaned_at IS NULL AND p.last_validated <= $1)
                            OR
                            (p.orphaned_at IS NOT NULL
                             AND p.orphaned_at <= $2
                             AND p.last_validated <= $2)
                       )
                       AND (p.last_binding_failure IS NULL OR p.last_binding_failure <= $3)
                     ORDER BY p.last_validated ASC NULLS FIRST, p.updated_at ASC, p.id ASC
                     LIMIT $4"
                );
                records.extend(
                    conn.query(
                        &sql,
                        &[&valid_before, &orphaned_before, &retry_before, &valid_limit],
                    )?
                    .iter()
                    .map(proxy_record_from_join_row),
                );
            }

            if invalid_limit > 0 {
                let sql = format!(
                    "SELECT {columns}
                     FROM proxies p
                     LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                     WHERE p.is_valid = FALSE
                       AND p.orphaned_at IS NULL
                       AND p.error_count < $1
                       AND (p.last_validated IS NOT NULL OR p.error_count > 0)
                       AND p.updated_at <= $2
                       AND (p.last_binding_failure IS NULL OR p.last_binding_failure <= $2)
                     ORDER BY p.error_count ASC, p.updated_at ASC, p.id ASC
                     LIMIT $3"
                );
                records.extend(
                    conn.query(&sql, &[&error_threshold, &retry_before, &invalid_limit])?
                        .iter()
                        .map(proxy_record_from_join_row),
                );
            }

            // Keep the configured cohorts fair, but do not leave validation
            // ports idle when the recheck/retry cohorts are temporarily small.
            // New inventory is normally the large backlog, so it absorbs only
            // the unused quota after the reserved cohorts were queried.
            let target = (new_limit + valid_limit + invalid_limit) as usize;
            let missing = target.saturating_sub(records.len()) as i64;
            if missing > 0 && new_limit > 0 {
                let sql = format!(
                    "SELECT {columns}
                     FROM proxies p
                     LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                     WHERE p.is_valid = FALSE
                       AND p.last_validated IS NULL
                       AND p.error_count = 0
                       AND p.orphaned_at IS NULL
                       AND (p.last_binding_failure IS NULL OR p.last_binding_failure <= $1)
                     ORDER BY p.created_at ASC, p.id ASC
                     LIMIT $2 OFFSET $3"
                );
                records.extend(
                    conn.query(&sql, &[&retry_before, &missing, &new_limit])?
                        .iter()
                        .map(proxy_record_from_join_row),
                );
            }

            Ok(records)
        })
    }

    pub fn get_stale_valid_recheck_ids(
        &self,
        validated_before: &str,
        limit: usize,
    ) -> Result<Vec<String>, postgres::Error> {
        let limit = limit as i64;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id
                 FROM proxies
                 WHERE is_valid = TRUE
                   AND orphaned_at IS NULL
                   AND error_count = 0
                   AND (last_validated IS NULL OR last_validated <= $1)
                 ORDER BY last_validated ASC NULLS FIRST, updated_at ASC
                 LIMIT $2",
                &[&validated_before, &limit],
            )?;
            Ok(rows.iter().map(|row| row.get::<_, String>(0)).collect())
        })
    }

    pub fn get_invalid_retry_ids(
        &self,
        max_error_count: u32,
        retry_before: &str,
        limit: usize,
    ) -> Result<Vec<String>, postgres::Error> {
        let max_error_count = max_error_count as i32;
        let limit = limit as i64;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id
                 FROM proxies
                 WHERE is_valid = FALSE
                   AND last_validated IS NOT NULL
                   AND error_count < $1
                   AND orphaned_at IS NULL
                   AND updated_at <= $2
                 ORDER BY error_count ASC, updated_at ASC
                 LIMIT $3",
                &[&max_error_count, &retry_before, &limit],
            )?;
            Ok(rows.iter().map(|row| row.get::<_, String>(0)).collect())
        })
    }

    pub fn delete_orphaned_non_valid_before(&self, cutoff: &str) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM proxy_quality WHERE proxy_id IN (
                    SELECT id FROM proxies
                    WHERE is_valid = FALSE
                      AND orphaned_at IS NOT NULL
                      AND orphaned_at <= $1
                 )",
                &[&cutoff],
            )?;
            let count = conn.execute(
                "DELETE FROM proxies
                 WHERE is_valid = FALSE
                   AND orphaned_at IS NOT NULL
                   AND orphaned_at <= $1",
                &[&cutoff],
            )?;
            Ok(count as usize)
        })
    }

    pub fn get_orphaned_valid_recheck_ids(
        &self,
        cutoff: &str,
        limit: usize,
    ) -> Result<Vec<String>, postgres::Error> {
        let limit = limit as i64;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id
                 FROM proxies
                 WHERE is_valid = TRUE
                   AND orphaned_at IS NOT NULL
                   AND orphaned_at <= $1
                   AND (last_validated IS NULL OR last_validated <= $1)
                 ORDER BY orphaned_at ASC, last_validated ASC NULLS FIRST, updated_at ASC
                 LIMIT $2",
                &[&cutoff, &limit],
            )?;
            Ok(rows.iter().map(|row| row.get::<_, String>(0)).collect())
        })
    }

    pub fn count_all_proxies(&self) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            let count: i64 = conn.query_one("SELECT COUNT(*) FROM proxies", &[])?.get(0);
            Ok(count as usize)
        })
    }

    pub fn count_valid_proxies(&self) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            let count: i64 = conn
                .query_one("SELECT COUNT(*) FROM proxies WHERE is_valid = TRUE", &[])?
                .get(0);
            Ok(count as usize)
        })
    }

    pub fn count_untested_proxies(&self) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            let count: i64 = conn
                .query_one(
                    "SELECT COUNT(*) FROM proxies
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
        // Cursor requests already have their totals from the first page. Avoid
        // repeating a million-row COUNT on every next/previous click.
        let counts_available = cursor.is_none();
        let (filtered, total) = if counts_available {
            self.with_conn(|conn| {
                let count_refs: Vec<&(dyn ToSql + Sync)> = count_params
                    .iter()
                    .map(|p| &**p as &(dyn ToSql + Sync))
                    .collect();
                let sql = format!(
                    "SELECT
                        COUNT(*) AS filtered,
                        (SELECT COUNT(*) FROM proxies WHERE orphaned_at IS NULL) AS total
                     FROM proxies p
                     LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                     {where_clause}"
                );
                let row = conn.query_one(&sql, &count_refs)?;
                let filtered: i64 = row.get("filtered");
                let total: i64 = row.get("total");
                Ok((filtered as usize, total as usize))
            })?
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

        self.with_conn(|conn| {
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
                 FROM proxies p
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
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
                 FROM proxies WHERE subscription_id = $1 ORDER BY name",
                &[&sub_id],
            )?;
            Ok(rows.iter().map(proxy_from_row).collect())
        })
    }

    pub fn delete_proxy(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM proxy_quality WHERE proxy_id = $1", &[&id])?;
            conn.execute("DELETE FROM proxies WHERE id = $1", &[&id])?;
            Ok(())
        })
    }

    pub fn delete_proxies_by_subscription(&self, sub_id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM proxy_quality WHERE proxy_id IN (
                    SELECT id FROM proxies WHERE subscription_id = $1
                 )",
                &[&sub_id],
            )?;
            conn.execute("DELETE FROM proxies WHERE subscription_id = $1", &[&sub_id])?;
            Ok(())
        })
    }

    pub fn update_proxy_validation(
        &self,
        id: &str,
        is_valid: bool,
        error: Option<&str>,
    ) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            if is_valid {
                conn.execute(
                    "UPDATE proxies
                     SET is_valid = TRUE, error_count = 0, last_error = NULL, last_validated = $1, updated_at = $1
                     WHERE id = $2",
                    &[&now, &id],
                )?;
            } else {
                let err = error.map(|s| s.to_string());
                conn.execute(
                    "UPDATE proxies
                     SET is_valid = FALSE, error_count = error_count + 1, last_error = $1, last_validated = $2, updated_at = $2
                     WHERE id = $3",
                    &[&err, &now, &id],
                )?;
            }
            Ok(())
        })
    }

    /// Return every inventory row that describes the same connectable node as
    /// `source_id`. Subscription ownership and display tags are deliberately
    /// ignored, while credentials, TLS and transport settings remain part of
    /// the identity.
    pub fn get_exact_duplicate_proxy_ids(
        &self,
        source_id: &str,
    ) -> Result<Vec<String>, postgres::Error> {
        self.with_conn(|conn| {
            let Some(source_row) = conn.query_opt(
                "SELECT id, subscription_id, name, proxy_type, server, port, config_json,
                        is_valid, local_port, error_count, last_error, last_validated,
                        created_at, updated_at, orphaned_at
                 FROM proxies WHERE id = $1",
                &[&source_id],
            )?
            else {
                return Ok(Vec::new());
            };
            let source = proxy_from_row(&source_row);
            let source_key = crate::api::subscription::proxy_row_definition_key(&source);
            let rows = conn.query(
                "SELECT id, subscription_id, name, proxy_type, server, port, config_json,
                        is_valid, local_port, error_count, last_error, last_validated,
                        created_at, updated_at, orphaned_at
                 FROM proxies
                 WHERE LOWER(server) = LOWER($1) AND port = $2 AND LOWER(proxy_type) = LOWER($3)",
                &[&source.server, &source.port, &source.proxy_type],
            )?;
            Ok(rows
                .iter()
                .map(proxy_from_row)
                .filter(|proxy| {
                    crate::api::subscription::proxy_row_definition_key(proxy) == source_key
                })
                .map(|proxy| proxy.id)
                .collect())
        })
    }

    /// Reuse already-known health and quality for newly inserted exact
    /// duplicates. The source rows remain in the inventory so subscription
    /// provenance is preserved, but no duplicate network probe is needed.
    pub fn inherit_exact_duplicate_states(
        &self,
        target_ids: &[String],
    ) -> Result<(), postgres::Error> {
        for target_id in target_ids {
            let duplicate_ids = self.get_exact_duplicate_proxy_ids(target_id)?;
            let donor = duplicate_ids
                .iter()
                .filter(|id| *id != target_id)
                .filter_map(|id| self.get_proxy_record(id).ok().flatten())
                .filter(|(proxy, _)| proxy.last_validated.is_some())
                .max_by(|(left, _), (right, _)| left.last_validated.cmp(&right.last_validated));
            let Some((donor, donor_quality)) = donor else {
                continue;
            };

            self.with_conn(|conn| {
                let mut tx = conn.transaction()?;
                tx.execute(
                    "UPDATE proxies
                     SET is_valid = $1, error_count = $2, last_error = $3,
                         last_validated = $4, local_port = NULL, updated_at = $5
                     WHERE id = $6",
                    &[
                        &donor.is_valid,
                        &donor.error_count,
                        &donor.last_error,
                        &donor.last_validated,
                        &donor.updated_at,
                        &target_id,
                    ],
                )?;
                if let Some(quality) = donor_quality {
                    tx.execute(
                        "INSERT INTO proxy_quality (
                            proxy_id, ip_address, country, ip_type, is_residential,
                            chatgpt_accessible, google_accessible, risk_score, risk_level,
                            extra_json, checked_at
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                         ON CONFLICT (proxy_id) DO UPDATE SET
                            ip_address = EXCLUDED.ip_address,
                            country = EXCLUDED.country,
                            ip_type = EXCLUDED.ip_type,
                            is_residential = EXCLUDED.is_residential,
                            chatgpt_accessible = EXCLUDED.chatgpt_accessible,
                            google_accessible = EXCLUDED.google_accessible,
                            risk_score = EXCLUDED.risk_score,
                            risk_level = EXCLUDED.risk_level,
                            extra_json = EXCLUDED.extra_json,
                            checked_at = EXCLUDED.checked_at",
                        &[
                            &target_id,
                            &quality.ip_address,
                            &quality.country,
                            &quality.ip_type,
                            &quality.is_residential,
                            &quality.chatgpt_accessible,
                            &quality.google_accessible,
                            &quality.risk_score,
                            &quality.risk_level,
                            &quality.extra_json,
                            &quality.checked_at,
                        ],
                    )?;
                }
                tx.commit()
            })?;
        }
        Ok(())
    }

    /// Persist one validation result for all exact copies and return their IDs
    /// so the in-memory hot pool can be kept consistent with the database.
    pub fn update_exact_duplicate_validation(
        &self,
        source_id: &str,
        is_valid: bool,
        error: Option<&str>,
        exit_ip: Option<&str>,
    ) -> Result<Vec<String>, postgres::Error> {
        let ids = self.get_exact_duplicate_proxy_ids(source_id)?;
        let now = chrono::Utc::now().to_rfc3339();
        let err = error.map(str::to_string);
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            for id in &ids {
                if is_valid {
                    tx.execute(
                        "UPDATE proxies
                         SET is_valid = TRUE, error_count = 0, last_error = NULL,
                             last_validated = $1, updated_at = $1
                         WHERE id = $2",
                        &[&now, id],
                    )?;
                } else {
                    tx.execute(
                        "UPDATE proxies
                         SET is_valid = FALSE, error_count = error_count + 1,
                             last_error = $1, last_validated = $2, updated_at = $2
                         WHERE id = $3",
                        &[&err, &now, id],
                    )?;
                }
                if let Some(exit_ip) = exit_ip {
                    upsert_exit_ip_tx(&mut tx, id, exit_ip, &now)?;
                }
            }
            tx.commit()?;
            Ok(())
        })?;
        Ok(ids)
    }

    /// Save the exit address observed during validation without erasing richer
    /// country/risk/capability fields collected by the quality checker.
    pub fn upsert_proxy_exit_ip(
        &self,
        proxy_id: &str,
        exit_ip: &str,
    ) -> Result<(), postgres::Error> {
        let checked_at = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO proxy_quality (
                    proxy_id, ip_address, country, ip_type, is_residential,
                    chatgpt_accessible, google_accessible, risk_score, risk_level,
                    extra_json, checked_at
                 ) VALUES ($1, $2, NULL, NULL, FALSE, FALSE, FALSE, 1.0, 'Unknown', NULL, $3)
                 ON CONFLICT (proxy_id) DO UPDATE SET
                    ip_address = EXCLUDED.ip_address,
                    country = CASE
                        WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                        THEN NULL ELSE proxy_quality.country END,
                    ip_type = CASE
                        WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                        THEN NULL ELSE proxy_quality.ip_type END,
                    is_residential = CASE
                        WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                        THEN FALSE ELSE proxy_quality.is_residential END,
                    chatgpt_accessible = CASE
                        WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                        THEN FALSE ELSE proxy_quality.chatgpt_accessible END,
                    google_accessible = CASE
                        WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                        THEN FALSE ELSE proxy_quality.google_accessible END,
                    risk_score = CASE
                        WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                        THEN 1.0 ELSE proxy_quality.risk_score END,
                    risk_level = CASE
                        WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                        THEN 'Unknown' ELSE proxy_quality.risk_level END,
                    extra_json = CASE
                        WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                        THEN NULL ELSE proxy_quality.extra_json END,
                    checked_at = CASE
                        WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                        THEN EXCLUDED.checked_at ELSE proxy_quality.checked_at END",
                &[&proxy_id, &exit_ip, &checked_at],
            )?;
            Ok(())
        })
    }

    pub fn mark_proxy_relay_failed(&self, id: &str, error: &str) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let err = error.to_string();
        let ids = self.get_exact_duplicate_proxy_ids(id)?;
        self.with_conn(|conn| {
            for duplicate_id in &ids {
                conn.execute(
                    "UPDATE proxies
                     SET is_valid = FALSE,
                         error_count = error_count + 1,
                         last_error = $1,
                         last_validated = NULL,
                         local_port = NULL,
                         updated_at = $2
                     WHERE id = $3",
                    &[&err, &now, duplicate_id],
                )?;
            }
            Ok(())
        })
    }

    pub fn reset_proxy_to_untested(&self, id: &str) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies
                 SET is_valid = FALSE, last_error = NULL, last_validated = NULL, local_port = NULL, updated_at = $1
                 WHERE id = $2",
                &[&now, &id],
            )?;
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
                "UPDATE proxies SET local_port = $1 WHERE id = $2",
                &[&local_port, &id],
            )?;
            Ok(())
        })
    }

    pub fn increment_proxy_error_count(&self, id: &str) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies SET error_count = error_count + 1, updated_at = $1 WHERE id = $2",
                &[&now, &id],
            )?;
            Ok(())
        })
    }

    pub fn update_proxy_config(
        &self,
        id: &str,
        name: &str,
        config_json: &str,
    ) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies
                 SET name = $1, config_json = $2, orphaned_at = NULL, updated_at = $3
                 WHERE id = $4",
                &[&name, &config_json, &now, &id],
            )?;
            Ok(())
        })
    }

    /// Reset health metadata when credentials or transport settings change for
    /// an otherwise identical endpoint.
    pub fn reset_proxy_after_config_change(
        &self,
        id: &str,
        name: &str,
        config_json: &str,
    ) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            tx.execute("DELETE FROM proxy_quality WHERE proxy_id = $1", &[&id])?;
            tx.execute(
                "UPDATE proxies
                 SET name = $1, config_json = $2, is_valid = FALSE,
                     local_port = NULL, error_count = 0, last_error = NULL,
                     last_validated = NULL, orphaned_at = NULL,
                     binding_failure_count = 0, last_binding_failure = NULL,
                     updated_at = $3
                 WHERE id = $4",
                &[&name, &config_json, &now, &id],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Persist a local binding failure separately from remote validation errors.
    pub fn record_proxy_binding_failure(&self, id: &str) -> Result<u32, postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            let row = conn.query_one(
                "UPDATE proxies
                 SET binding_failure_count = binding_failure_count + 1,
                     last_binding_failure = $1,
                     last_error = 'sing-box binding failed',
                     local_port = NULL
                 WHERE id = $2
                 RETURNING binding_failure_count",
                &[&now, &id],
            )?;
            let failures: i32 = row.get(0);
            Ok(failures.max(0) as u32)
        })
    }

    pub fn clear_proxy_binding_failures(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies
                 SET binding_failure_count = 0, last_binding_failure = NULL,
                     last_error = CASE
                         WHEN last_error = 'sing-box binding failed' THEN NULL
                         ELSE last_error
                     END
                 WHERE id = $1 AND binding_failure_count > 0",
                &[&id],
            )?;
            Ok(())
        })
    }

    pub fn mark_proxy_orphaned(&self, id: &str, orphaned_at: &str) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies
                 SET orphaned_at = COALESCE(orphaned_at, $1), updated_at = $2
                 WHERE id = $3",
                &[&orphaned_at, &now, &id],
            )?;
            Ok(())
        })
    }

    pub fn delete_proxy_if_orphaned(&self, id: &str) -> Result<bool, postgres::Error> {
        self.with_conn(|conn| {
            let orphaned = conn
                .query_opt("SELECT orphaned_at FROM proxies WHERE id = $1", &[&id])?
                .and_then(|row| row.get::<_, Option<String>>(0))
                .is_some();

            if !orphaned {
                return Ok(false);
            }

            conn.execute("DELETE FROM proxy_quality WHERE proxy_id = $1", &[&id])?;
            conn.execute("DELETE FROM proxies WHERE id = $1", &[&id])?;
            Ok(true)
        })
    }

    pub fn update_proxy_local_port_null(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute("UPDATE proxies SET local_port = NULL WHERE id = $1", &[&id])?;
            Ok(())
        })
    }

    pub fn clear_all_proxy_local_ports(&self) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies SET local_port = NULL WHERE local_port IS NOT NULL",
                &[],
            )?;
            Ok(())
        })
    }

    pub fn cleanup_high_error_proxies(&self, threshold: u32) -> Result<usize, postgres::Error> {
        let threshold = threshold as i32;
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM proxy_quality WHERE proxy_id IN (
                    SELECT id FROM proxies WHERE error_count >= $1
                 )",
                &[&threshold],
            )?;
            let count =
                conn.execute("DELETE FROM proxies WHERE error_count >= $1", &[&threshold])?;
            Ok(count as usize)
        })
    }

    pub fn upsert_quality(&self, q: &ProxyQuality) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO proxy_quality (
                    proxy_id, ip_address, country, ip_type, is_residential, chatgpt_accessible,
                    google_accessible, risk_score, risk_level, extra_json, checked_at
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6,
                    $7, $8, $9, $10, $11
                 )
                 ON CONFLICT (proxy_id) DO UPDATE SET
                    ip_address = EXCLUDED.ip_address,
                    country = EXCLUDED.country,
                    ip_type = EXCLUDED.ip_type,
                    is_residential = EXCLUDED.is_residential,
                    chatgpt_accessible = EXCLUDED.chatgpt_accessible,
                    google_accessible = EXCLUDED.google_accessible,
                    risk_score = EXCLUDED.risk_score,
                    risk_level = EXCLUDED.risk_level,
                    extra_json = EXCLUDED.extra_json,
                    checked_at = EXCLUDED.checked_at",
                &[
                    &q.proxy_id,
                    &q.ip_address,
                    &q.country,
                    &q.ip_type,
                    &q.is_residential,
                    &q.chatgpt_accessible,
                    &q.google_accessible,
                    &q.risk_score,
                    &q.risk_level,
                    &q.extra_json,
                    &q.checked_at,
                ],
            )?;
            Ok(())
        })
    }

    /// Save one quality result for every source row that represents the same
    /// complete proxy definition. This preserves subscription provenance while
    /// avoiding duplicate capability probes.
    pub fn upsert_exact_duplicate_quality(
        &self,
        source_id: &str,
        quality: &ProxyQuality,
    ) -> Result<Vec<String>, postgres::Error> {
        let ids = self.get_exact_duplicate_proxy_ids(source_id)?;
        for id in &ids {
            let mut copy = quality.clone();
            copy.proxy_id = id.clone();
            self.upsert_quality(&copy)?;
        }
        Ok(ids)
    }

    pub fn get_quality(&self, proxy_id: &str) -> Result<Option<ProxyQuality>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT proxy_id, ip_address, country, ip_type, is_residential,
                        chatgpt_accessible, google_accessible, risk_score, risk_level,
                        extra_json, checked_at
                 FROM proxy_quality WHERE proxy_id = $1",
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
                 FROM proxy_quality",
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
                 FROM proxies p
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
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
                 FROM proxy_quality q
                 JOIN proxies p ON p.id = q.proxy_id
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
                 FROM proxies
                 WHERE orphaned_at IS NULL
                 GROUP BY proxy_type",
                &[],
            )?;
            let by_country_rows = conn.query(
                "SELECT q.country, COUNT(DISTINCT q.ip_address)
                 FROM proxy_quality q
                 JOIN proxies p ON p.id = q.proxy_id
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

fn upsert_exit_ip_tx(
    tx: &mut postgres::Transaction<'_>,
    proxy_id: &str,
    exit_ip: &str,
    checked_at: &str,
) -> Result<(), postgres::Error> {
    tx.execute(
        "INSERT INTO proxy_quality (
            proxy_id, ip_address, country, ip_type, is_residential,
            chatgpt_accessible, google_accessible, risk_score, risk_level,
            extra_json, checked_at
         ) VALUES ($1, $2, NULL, NULL, FALSE, FALSE, FALSE, 1.0, 'Unknown', NULL, $3)
         ON CONFLICT (proxy_id) DO UPDATE SET
            ip_address = EXCLUDED.ip_address,
            country = CASE
                WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                THEN NULL ELSE proxy_quality.country END,
            ip_type = CASE
                WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                THEN NULL ELSE proxy_quality.ip_type END,
            is_residential = CASE
                WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                THEN FALSE ELSE proxy_quality.is_residential END,
            chatgpt_accessible = CASE
                WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                THEN FALSE ELSE proxy_quality.chatgpt_accessible END,
            google_accessible = CASE
                WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                THEN FALSE ELSE proxy_quality.google_accessible END,
            risk_score = CASE
                WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                THEN 1.0 ELSE proxy_quality.risk_score END,
            risk_level = CASE
                WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                THEN 'Unknown' ELSE proxy_quality.risk_level END,
            extra_json = CASE
                WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                THEN NULL ELSE proxy_quality.extra_json END,
            checked_at = CASE
                WHEN proxy_quality.ip_address IS DISTINCT FROM EXCLUDED.ip_address
                THEN EXCLUDED.checked_at ELSE proxy_quality.checked_at END",
        &[&proxy_id, &exit_ip, &checked_at],
    )?;
    Ok(())
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
                OR NOT EXISTS (
                    SELECT 1
                    FROM proxy_quality better_q
                    JOIN proxies better_p ON better_p.id = better_q.proxy_id
                    WHERE better_p.orphaned_at IS NULL
                      AND better_q.ip_address = q.ip_address
                      AND (
                        (better_p.is_valid = TRUE AND p.is_valid = FALSE)
                        OR (
                            better_p.is_valid = p.is_valid
                            AND better_p.error_count < p.error_count
                        )
                        OR (
                            better_p.is_valid = p.is_valid
                            AND better_p.error_count = p.error_count
                            AND COALESCE(better_p.last_validated, '') > COALESCE(p.last_validated, '')
                        )
                        OR (
                            better_p.is_valid = p.is_valid
                            AND better_p.error_count = p.error_count
                            AND COALESCE(better_p.last_validated, '') = COALESCE(p.last_validated, '')
                            AND better_p.updated_at > p.updated_at
                        )
                        OR (
                            better_p.is_valid = p.is_valid
                            AND better_p.error_count = p.error_count
                            AND COALESCE(better_p.last_validated, '') = COALESCE(p.last_validated, '')
                            AND better_p.updated_at = p.updated_at
                            AND better_p.id < p.id
                        )
                      )
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

fn build_fetch_proxy_where(
    filter: &crate::pool::manager::ProxyFilter,
    params: &mut Vec<Box<dyn ToSql + Sync>>,
    only_valid: bool,
) -> String {
    let mut conditions = Vec::new();

    if only_valid {
        conditions.push("p.is_valid = TRUE".to_string());
        conditions.push("p.orphaned_at IS NULL".to_string());
        // Public selection must have a measured exit IP so DISTINCT ON can
        // guarantee that one response never contains the same exit twice.
        conditions.push("q.ip_address IS NOT NULL".to_string());
        conditions.push("BTRIM(q.ip_address) <> ''".to_string());
    }

    if let Some(proxy_type) = filter
        .proxy_type
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        params.push(Box::new(proxy_type.to_string()));
        let idx = params.len();
        conditions.push(format!("p.proxy_type = ${idx}"));
    }

    if filter.chatgpt {
        conditions.push("q.chatgpt_accessible = TRUE".to_string());
    }

    if filter.google {
        conditions.push("q.google_accessible = TRUE".to_string());
    }

    if filter.residential {
        conditions.push("q.is_residential = TRUE".to_string());
    }

    if let Some(max_risk) = filter.risk_max {
        params.push(Box::new(max_risk));
        let idx = params.len();
        conditions.push(format!("q.risk_score <= ${idx}"));
    }

    if let Some(country) = filter
        .country
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        params.push(Box::new(country.to_string()));
        let idx = params.len();
        conditions.push(format!("LOWER(q.country) = LOWER(${idx})"));
    }

    if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    }
}

fn build_random_valid_proxy_order_by(
    params: &mut Vec<Box<dyn ToSql + Sync>>,
    recent_error_before: Option<&str>,
) -> String {
    if let Some(cutoff) = recent_error_before {
        params.push(Box::new(cutoff.to_string()));
        let idx = params.len();
        format!(
            "CASE \
                WHEN p.error_count = 0 THEN 0 \
                WHEN p.updated_at <= ${idx} THEN 1 \
                ELSE 2 \
             END ASC, p.error_count ASC, RANDOM()"
        )
    } else {
        "p.error_count ASC, RANDOM()".to_string()
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
        build_fetch_proxy_where, build_proxy_list_where, build_random_valid_proxy_order_by,
        decode_proxy_list_cursor, encode_proxy_list_cursor, ProxyListCursor, ProxyListQuery,
    };
    use crate::pool::manager::ProxyFilter;
    use postgres::types::ToSql;

    #[test]
    fn build_fetch_proxy_where_does_not_exclude_recent_error_proxies() {
        let filter = ProxyFilter::default();
        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();

        let clause = build_fetch_proxy_where(&filter, &mut params, true);

        assert_eq!(
            clause,
            "WHERE p.is_valid = TRUE AND p.orphaned_at IS NULL AND q.ip_address IS NOT NULL AND BTRIM(q.ip_address) <> ''"
        );
        assert!(params.is_empty());
    }

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
    fn build_random_valid_proxy_order_by_deprioritizes_recent_failures_without_dropping_them() {
        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();

        let clause =
            build_random_valid_proxy_order_by(&mut params, Some("2026-03-26T00:00:00+00:00"));

        assert!(clause.contains("WHEN p.error_count = 0 THEN 0"));
        assert!(clause.contains("WHEN p.updated_at <= $1 THEN 1"));
        assert!(clause.contains("ELSE 2"));
        assert!(clause.contains("RANDOM()"));
        assert_eq!(params.len(), 1);
    }
}
