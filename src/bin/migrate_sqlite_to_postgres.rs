use postgres::{Client, NoTls, Transaction};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse()?;
    let db_name = validate_db_name(&args.db_name)?;

    let mut admin = Client::connect(&args.admin_url, NoTls)?;
    ensure_database_exists(&mut admin, db_name)?;

    let target_url = with_database_name(&args.admin_url, db_name)?;
    let mut pg = Client::connect(&target_url, NoTls)?;
    pg.batch_execute("SELECT pg_advisory_lock(1514491472, 1380931673)")?;
    init_schema(&mut pg)?;

    let existing: i64 = pg.query_one("SELECT COUNT(*) FROM subscriptions", &[])?.get(0);
    if existing > 0 {
        return Err(format!("target database '{db_name}' is not empty").into());
    }

    let sqlite = Connection::open_with_flags(&args.sqlite_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut tx = pg.transaction()?;
    migrate_subscriptions(&sqlite, &mut tx)?;
    let repaired = migrate_proxies(&sqlite, &mut tx)?;
    migrate_proxy_quality(&sqlite, &mut tx)?;
    backfill_normalized_tables(&mut tx)?;
    migrate_users(&sqlite, &mut tx)?;
    migrate_sessions(&sqlite, &mut tx)?;
    tx.commit()?;
    pg.batch_execute("SELECT pg_advisory_unlock(1514491472, 1380931673)")?;

    println!("migration complete");
    println!("target database: {db_name}");
    println!("target url: {target_url}");
    println!("repaired proxies reset from 'binding creation failed': {repaired}");

    Ok(())
}

struct Args {
    admin_url: String,
    db_name: String,
    sqlite_path: String,
}

impl Args {
    fn parse() -> Result<Self, Box<dyn Error>> {
        let mut admin_url = None;
        let mut db_name = String::from("zenproxy");
        let mut sqlite_path = String::from("data/zenproxy.db");

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--admin-url" => admin_url = args.next(),
                "--db-name" => {
                    db_name = args
                        .next()
                        .ok_or("--db-name requires a value")?;
                }
                "--sqlite-path" => {
                    sqlite_path = args
                        .next()
                        .ok_or("--sqlite-path requires a value")?;
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                _ => return Err(format!("unknown argument: {arg}").into()),
            }
        }

        let admin_url = admin_url.ok_or("--admin-url is required")?;

        Ok(Self {
            admin_url,
            db_name,
            sqlite_path,
        })
    }
}

fn print_usage() {
    eprintln!(
        "Usage: migrate_sqlite_to_postgres --admin-url <postgresql://.../postgres> [--db-name zenproxy] [--sqlite-path data/zenproxy.db]"
    );
}

fn validate_db_name(db_name: &str) -> Result<&str, Box<dyn Error>> {
    if db_name.is_empty() {
        return Err("database name cannot be empty".into());
    }
    if db_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        Ok(db_name)
    } else {
        Err("database name may only contain letters, numbers, and underscores".into())
    }
}

fn with_database_name(admin_url: &str, db_name: &str) -> Result<String, Box<dyn Error>> {
    let mut url = url::Url::parse(admin_url)?;
    url.set_path(&format!("/{db_name}"));
    Ok(url.to_string())
}

fn ensure_database_exists(admin: &mut Client, db_name: &str) -> Result<(), Box<dyn Error>> {
    let exists = admin
        .query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&db_name])?
        .is_some();
    if !exists {
        admin.batch_execute(&format!("CREATE DATABASE \"{db_name}\""))?;
    }
    Ok(())
}

fn init_schema(pg: &mut Client) -> Result<(), Box<dyn Error>> {
    pg.batch_execute(
        "
        CREATE OR REPLACE FUNCTION zenproxy_try_jsonb(value TEXT)
        RETURNS JSONB LANGUAGE plpgsql IMMUTABLE AS $$
        BEGIN
            IF value IS NULL OR BTRIM(value) = '' THEN RETURN NULL; END IF;
            RETURN value::jsonb;
        EXCEPTION WHEN OTHERS THEN RETURN NULL;
        END;
        $$;

        CREATE OR REPLACE FUNCTION zenproxy_try_inet(value TEXT)
        RETURNS INET LANGUAGE plpgsql IMMUTABLE AS $$
        BEGIN
            IF value IS NULL OR BTRIM(value) = '' THEN RETURN NULL; END IF;
            RETURN BTRIM(value)::inet;
        EXCEPTION WHEN OTHERS THEN RETURN NULL;
        END;
        $$;

        CREATE OR REPLACE FUNCTION zenproxy_rfc3339(value TIMESTAMPTZ)
        RETURNS TEXT LANGUAGE SQL IMMUTABLE AS $$
            SELECT CASE WHEN value IS NULL THEN NULL ELSE
                TO_CHAR(value AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
            END
        $$;

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
            updated_at TEXT NOT NULL,
            last_refresh_at_ts TIMESTAMPTZ,
            created_at_ts TIMESTAMPTZ,
            updated_at_ts TIMESTAMPTZ
        );

        CREATE TABLE IF NOT EXISTS proxies (
            id TEXT PRIMARY KEY,
            subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
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
            orphaned_at TEXT,
            definition_hash BYTEA NOT NULL,
            binding_failure_count INTEGER NOT NULL DEFAULT 0,
            last_binding_failure TEXT,
            created_at_ts TIMESTAMPTZ,
            updated_at_ts TIMESTAMPTZ,
            last_validated_ts TIMESTAMPTZ,
            orphaned_at_ts TIMESTAMPTZ,
            last_binding_failure_ts TIMESTAMPTZ
        );

        CREATE TABLE IF NOT EXISTS proxy_quality (
            proxy_id TEXT PRIMARY KEY REFERENCES proxies(id) ON DELETE CASCADE,
            ip_address TEXT,
            country TEXT,
            ip_type TEXT,
            is_residential BOOLEAN NOT NULL DEFAULT FALSE,
            chatgpt_accessible BOOLEAN NOT NULL DEFAULT FALSE,
            google_accessible BOOLEAN NOT NULL DEFAULT FALSE,
            risk_score DOUBLE PRECISION NOT NULL DEFAULT 1.0,
            risk_level TEXT NOT NULL DEFAULT 'Unknown',
            extra_json TEXT,
            checked_at TEXT NOT NULL,
            checked_at_ts TIMESTAMPTZ,
            extra_jsonb JSONB,
            schema_version INTEGER NOT NULL DEFAULT 0,
            incomplete_retry_count INTEGER NOT NULL DEFAULT 0
        );

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

        ALTER TABLE exit_quality ADD COLUMN IF NOT EXISTS chatgpt_accessible
            BOOLEAN NOT NULL DEFAULT FALSE;
        ALTER TABLE exit_quality ADD COLUMN IF NOT EXISTS google_accessible
            BOOLEAN NOT NULL DEFAULT FALSE;
        ALTER TABLE exit_quality ADD COLUMN IF NOT EXISTS extra_json JSONB;

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

        CREATE TABLE IF NOT EXISTS quality_retry_state (
            definition_id TEXT PRIMARY KEY REFERENCES proxy_definitions(id) ON DELETE CASCADE,
            extra_json JSONB NOT NULL,
            checked_at TIMESTAMPTZ NOT NULL
        );

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
               zenproxy_rfc3339(CASE
                   WHEN health.last_success_at IS NULL THEN health.last_failure_at
                   WHEN health.last_failure_at IS NULL THEN health.last_success_at
                   ELSE GREATEST(health.last_success_at, health.last_failure_at)
               END) AS last_validated,
               zenproxy_rfc3339(membership.created_at) AS created_at,
               zenproxy_rfc3339(GREATEST(
                   membership.updated_at, definition.updated_at, health.updated_at,
                   COALESCE(runtime.updated_at, membership.updated_at)
               )) AS updated_at,
               zenproxy_rfc3339(membership.orphaned_at) AS orphaned_at,
               definition.definition_hash,
               COALESCE(runtime.binding_failure_count, 0) AS binding_failure_count,
               zenproxy_rfc3339(runtime.last_binding_failure) AS last_binding_failure,
               membership.created_at AS created_at_ts,
               GREATEST(
                   membership.updated_at, definition.updated_at, health.updated_at,
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
               COALESCE(quality.chatgpt_accessible, FALSE) AS chatgpt_accessible,
               COALESCE(quality.google_accessible, FALSE) AS google_accessible,
               COALESCE(quality.risk_score, 1.0) AS risk_score,
               COALESCE(quality.risk_level, 'Unknown') AS risk_level,
               COALESCE(
                   quality.extra_json, retry.extra_json,
                   jsonb_build_object('unlock', quality.unlock_json)
               )::text AS extra_json,
               zenproxy_rfc3339(COALESCE(
                   quality.checked_at, retry.checked_at, observed.observed_at
               )) AS checked_at,
               COALESCE(quality.checked_at, retry.checked_at, observed.observed_at)
                   AS checked_at_ts,
               COALESCE(
                   quality.extra_json, retry.extra_json,
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
        LEFT JOIN proxy_exit observed ON observed.definition_id = membership.definition_id
        LEFT JOIN exit_quality quality ON quality.ip_address = observed.ip_address
        LEFT JOIN quality_retry_state retry ON retry.definition_id = membership.definition_id
        WHERE observed.ip_address IS NOT NULL OR retry.definition_id IS NOT NULL;

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

        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_normalized_url
            ON subscriptions ((BTRIM(url)))
            WHERE url IS NOT NULL AND BTRIM(url) <> '';
        CREATE INDEX IF NOT EXISTS idx_proxies_subscription_id ON proxies(subscription_id);
        CREATE INDEX IF NOT EXISTS idx_proxies_definition_hash_current
            ON proxies(definition_hash) WHERE orphaned_at IS NULL;
        CREATE INDEX IF NOT EXISTS idx_proxies_hot_selection
            ON proxies(is_valid, error_count, last_validated_ts DESC, updated_at_ts DESC)
            WHERE orphaned_at IS NULL;
        CREATE INDEX IF NOT EXISTS idx_proxies_last_validated_ts ON proxies(last_validated_ts);
        CREATE INDEX IF NOT EXISTS idx_proxies_error_count ON proxies(error_count);
        CREATE INDEX IF NOT EXISTS idx_proxy_quality_country_upper
            ON proxy_quality(UPPER(country), proxy_id);
        CREATE INDEX IF NOT EXISTS idx_proxy_quality_due_v2
            ON proxy_quality(schema_version, checked_at_ts, proxy_id);
        CREATE INDEX IF NOT EXISTS idx_subscription_proxies_subscription
            ON subscription_proxies(subscription_id, orphaned_at, definition_id);
        CREATE INDEX IF NOT EXISTS idx_proxy_definitions_type
            ON proxy_definitions(proxy_type, id);
        CREATE INDEX IF NOT EXISTS idx_proxy_health_due
            ON proxy_health(next_check_at, lease_until, definition_id);
        CREATE INDEX IF NOT EXISTS idx_proxy_exit_ip ON proxy_exit(ip_address, definition_id);
        CREATE INDEX IF NOT EXISTS idx_exit_quality_checked_at ON exit_quality(checked_at);
        CREATE INDEX IF NOT EXISTS idx_exit_quality_country_upper
            ON exit_quality(UPPER(country), ip_address);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_runtime_local_port
            ON proxy_runtime(local_port) WHERE local_port IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_quality_check_leases_until
            ON quality_check_leases(lease_until);
        ",
    )?;
    Ok(())
}

fn migrate_subscriptions(sqlite: &Connection, tx: &mut Transaction<'_>) -> Result<(), Box<dyn Error>> {
    let stmt = tx.prepare(
        "INSERT INTO subscriptions (
            id, name, sub_type, url, content, proxy_count, raw_proxy_count,
            duplicate_proxy_count, refresh_interval_mins, last_refresh_at,
            created_at, updated_at, last_refresh_at_ts, created_at_ts, updated_at_ts
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $6,
            0, $7, $8, $9, $10,
            NULLIF($8, '')::timestamptz, NULLIF($9, '')::timestamptz,
            NULLIF($10, '')::timestamptz
         )",
    )?;

    let mut query = sqlite.prepare(
        "SELECT id, name, sub_type, url, content, proxy_count, created_at, updated_at
         FROM subscriptions ORDER BY created_at ASC",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, i32>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
        ))
    })?;

    let mut claimed_urls = std::collections::HashSet::new();
    for row in rows {
        let (id, name, sub_type, mut url, content, proxy_count, created_at, updated_at) = row?;
        if let Some(normalized) = url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
        {
            if !claimed_urls.insert(normalized) {
                url = None;
            }
        }
        let refresh_interval_mins: Option<i32> = None;
        let last_refresh_at = Some(updated_at.clone());
        tx.execute(
            &stmt,
            &[
                &id,
                &name,
                &sub_type,
                &url,
                &content,
                &proxy_count,
                &refresh_interval_mins,
                &last_refresh_at,
                &created_at,
                &updated_at,
            ],
        )?;
    }

    Ok(())
}

fn migrate_proxies(sqlite: &Connection, tx: &mut Transaction<'_>) -> Result<usize, Box<dyn Error>> {
    let stmt = tx.prepare(
        "INSERT INTO proxies (
            id, subscription_id, name, proxy_type, server, port, config_json,
            is_valid, local_port, error_count, last_error, last_validated, created_at, updated_at,
            definition_hash, created_at_ts, updated_at_ts, last_validated_ts
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11, $12, $13, $14,
            $15, NULLIF($13, '')::timestamptz, NULLIF($14, '')::timestamptz,
            NULLIF($12, '')::timestamptz
         )",
    )?;

    let mut query = sqlite.prepare(
        "SELECT id, subscription_id, name, proxy_type, server, port, config_json,
                is_valid, local_port, error_count, last_error, last_validated, created_at, updated_at
         FROM proxies ORDER BY created_at ASC",
    )?;

    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i32>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, i32>(7)? != 0,
            row.get::<_, Option<i32>>(8)?,
            row.get::<_, i32>(9)?,
            row.get::<_, Option<String>>(10)?,
            row.get::<_, Option<String>>(11)?,
            row.get::<_, String>(12)?,
            row.get::<_, String>(13)?,
        ))
    })?;

    let mut repaired = 0usize;

    for row in rows {
        let (
            id,
            subscription_id,
            name,
            proxy_type,
            server,
            port,
            config_json,
            mut is_valid,
            mut local_port,
            mut error_count,
            mut last_error,
            mut last_validated,
            created_at,
            updated_at,
        ) = row?;

        if last_error.as_deref() == Some("binding creation failed") {
            is_valid = false;
            local_port = None;
            error_count = 0;
            last_error = None;
            last_validated = None;
            repaired += 1;
        }
        let definition_hash = proxy_definition_hash(
            &id,
            &proxy_type,
            &server,
            port,
            &config_json,
        );

        tx.execute(
            &stmt,
            &[
                &id,
                &subscription_id,
                &name,
                &proxy_type,
                &server,
                &port,
                &config_json,
                &is_valid,
                &local_port,
                &error_count,
                &last_error,
                &last_validated,
                &created_at,
                &updated_at,
                &definition_hash,
            ],
        )?;
    }

    Ok(repaired)
}

fn migrate_proxy_quality(sqlite: &Connection, tx: &mut Transaction<'_>) -> Result<(), Box<dyn Error>> {
    let stmt = tx.prepare(
        "INSERT INTO proxy_quality (
            proxy_id, ip_address, country, ip_type, is_residential, chatgpt_accessible,
            google_accessible, risk_score, risk_level, extra_json, checked_at,
            checked_at_ts, extra_jsonb, schema_version, incomplete_retry_count
         ) VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10, $11,
            NULLIF($11, '')::timestamptz,
            CASE WHEN $12::text IS NULL THEN NULL ELSE $12::text::jsonb END,
            $13, $14
         )",
    )?;

    let mut query = sqlite.prepare(
        "SELECT proxy_id, ip_address, country, ip_type, is_residential,
                chatgpt_accessible, google_accessible, risk_score, risk_level, extra_json, checked_at
         FROM proxy_quality",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, i32>(4)? != 0,
            row.get::<_, i32>(5)? != 0,
            row.get::<_, i32>(6)? != 0,
            row.get::<_, f64>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Option<String>>(9)?,
            row.get::<_, String>(10)?,
        ))
    })?;

    for row in rows {
        let (proxy_id, ip_address, country, ip_type, is_residential, chatgpt_accessible, google_accessible, risk_score, risk_level, extra_json, checked_at) = row?;
        let (valid_extra_json, schema_version, incomplete_retry_count) =
            quality_materialized_fields(extra_json.as_deref());
        tx.execute(
            &stmt,
            &[
                &proxy_id,
                &ip_address,
                &country,
                &ip_type,
                &is_residential,
                &chatgpt_accessible,
                &google_accessible,
                &risk_score,
                &risk_level,
                &extra_json,
                &checked_at,
                &valid_extra_json,
                &schema_version,
                &incomplete_retry_count,
            ],
        )?;
    }

    Ok(())
}

fn backfill_normalized_tables(tx: &mut Transaction<'_>) -> Result<(), Box<dyn Error>> {
    tx.batch_execute(
        "INSERT INTO proxy_definitions (
            id, identity_version, definition_hash, proxy_type, server, port,
            config_json, created_at, updated_at
         )
         SELECT gen_random_uuid()::text, 1, selected.definition_hash,
                selected.proxy_type, selected.server, selected.port,
                COALESCE(zenproxy_try_jsonb(selected.config_json), '{}'::jsonb),
                selected.created_at_ts, selected.updated_at_ts
         FROM (
            SELECT DISTINCT ON (definition_hash) *
            FROM proxies
            ORDER BY definition_hash, updated_at_ts DESC NULLS LAST, id
         ) selected
         ON CONFLICT (definition_hash) DO NOTHING;

         INSERT INTO subscription_proxies (
            source_proxy_id, subscription_id, definition_id, display_name,
            orphaned_at, created_at, updated_at
         )
         SELECT p.id, p.subscription_id, definition.id, p.name,
                p.orphaned_at_ts, p.created_at_ts, p.updated_at_ts
         FROM proxies p
         JOIN proxy_definitions definition
           ON definition.definition_hash = p.definition_hash
         ON CONFLICT (source_proxy_id) DO NOTHING;

         INSERT INTO proxy_health (
            definition_id, health_state, consecutive_failures,
            last_success_at, last_failure_at, next_check_at,
            failure_kind, last_error, updated_at
         )
         SELECT DISTINCT ON (definition.id)
                definition.id,
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
                p.updated_at_ts
         FROM proxies p
         JOIN proxy_definitions definition
           ON definition.definition_hash = p.definition_hash
         ORDER BY definition.id, p.last_validated_ts DESC NULLS LAST,
                  p.updated_at_ts DESC NULLS LAST, p.id
         ON CONFLICT (definition_id) DO NOTHING;

         INSERT INTO proxy_runtime (
            definition_id, local_port, binding_owner_id, binding_failure_count,
            last_binding_failure, updated_at
         )
         SELECT DISTINCT ON (definition.id)
                definition.id, p.local_port,
                CASE WHEN p.local_port IS NULL THEN NULL ELSE p.id END,
                p.binding_failure_count,
                p.last_binding_failure_ts, p.updated_at_ts
         FROM proxies p
         JOIN proxy_definitions definition
           ON definition.definition_hash = p.definition_hash
         ORDER BY definition.id, CASE WHEN p.local_port IS NULL THEN 1 ELSE 0 END,
                  p.updated_at_ts DESC NULLS LAST, p.id
         ON CONFLICT (definition_id) DO NOTHING;

         INSERT INTO proxy_exit (definition_id, ip_address, observed_at)
         SELECT DISTINCT ON (definition.id)
                definition.id, zenproxy_try_inet(q.ip_address), q.checked_at_ts
         FROM proxies p
         JOIN proxy_definitions definition
           ON definition.definition_hash = p.definition_hash
         JOIN proxy_quality q ON q.proxy_id = p.id
         WHERE zenproxy_try_inet(q.ip_address) IS NOT NULL
         ORDER BY definition.id, q.checked_at_ts DESC NULLS LAST, p.id
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
                q.checked_at_ts, definition.id
         FROM proxy_quality q
         JOIN proxies p ON p.id = q.proxy_id
         JOIN proxy_definitions definition
           ON definition.definition_hash = p.definition_hash
         WHERE zenproxy_try_inet(q.ip_address) IS NOT NULL
         ORDER BY zenproxy_try_inet(q.ip_address), q.checked_at_ts DESC NULLS LAST,
                  q.proxy_id
         ON CONFLICT (ip_address) DO NOTHING;",
    )?;
    Ok(())
}

fn migrate_users(sqlite: &Connection, tx: &mut Transaction<'_>) -> Result<(), Box<dyn Error>> {
    let stmt = tx.prepare(
        "INSERT INTO users (
            id, username, name, avatar_template, active, trust_level, silenced,
            is_banned, api_key, created_at, updated_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11
         )",
    )?;

    let mut query = sqlite.prepare(
        "SELECT id, username, name, avatar_template, active, trust_level, silenced,
                is_banned, api_key, created_at, updated_at
         FROM users ORDER BY created_at ASC",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, i32>(4)? != 0,
            row.get::<_, i32>(5)?,
            row.get::<_, i32>(6)? != 0,
            row.get::<_, i32>(7)? != 0,
            row.get::<_, String>(8)?,
            row.get::<_, String>(9)?,
            row.get::<_, String>(10)?,
        ))
    })?;

    for row in rows {
        let (id, username, name, avatar_template, active, trust_level, silenced, is_banned, api_key, created_at, updated_at) = row?;
        tx.execute(
            &stmt,
            &[
                &id,
                &username,
                &name,
                &avatar_template,
                &active,
                &trust_level,
                &silenced,
                &is_banned,
                &api_key,
                &created_at,
                &updated_at,
            ],
        )?;
    }

    Ok(())
}

fn migrate_sessions(sqlite: &Connection, tx: &mut Transaction<'_>) -> Result<(), Box<dyn Error>> {
    let stmt = tx.prepare(
        "INSERT INTO sessions (id, user_id, created_at, expires_at)
         VALUES ($1, $2, $3, $4)",
    )?;

    let mut query = sqlite.prepare(
        "SELECT id, user_id, created_at, expires_at
         FROM sessions ORDER BY created_at ASC",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    for row in rows {
        let (id, user_id, created_at, expires_at) = row?;
        tx.execute(&stmt, &[&id, &user_id, &created_at, &expires_at])?;
    }

    Ok(())
}

fn proxy_definition_hash(
    id: &str,
    proxy_type: &str,
    server: &str,
    port: i32,
    config_json: &str,
) -> Vec<u8> {
    let definition = serde_json::from_str::<serde_json::Value>(config_json)
        .map(|mut outbound| {
            if let Some(object) = outbound.as_object_mut() {
                object.remove("tag");
                if let Some(serde_json::Value::String(value)) = object.get_mut("server") {
                    *value = value.to_ascii_lowercase();
                }
            }
            format!(
                "{}\u{1f}{}\u{1f}{}\u{1f}{}",
                proxy_type.to_ascii_lowercase(),
                server.to_ascii_lowercase(),
                port as u16,
                canonical_json(&outbound)
            )
        })
        .unwrap_or_else(|_| format!("invalid\u{1f}{id}"));
    Sha256::digest(definition.as_bytes()).to_vec()
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_unstable();
            let fields = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        canonical_json(&object[key])
                    )
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", fields.join(","))
        }
        serde_json::Value::Array(array) => format!(
            "[{}]",
            array
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => value.to_string(),
    }
}

fn quality_materialized_fields(extra_json: Option<&str>) -> (Option<String>, i32, i32) {
    let parsed = extra_json.and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
    let schema_version = parsed
        .as_ref()
        .and_then(|value| value.get("schema_version"))
        .and_then(serde_json::Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or(0);
    let incomplete_retry_count = parsed
        .as_ref()
        .and_then(|value| value.get("incomplete_retry_count"))
        .and_then(serde_json::Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or(0);
    (
        parsed.map(|value| value.to_string()),
        schema_version,
        incomplete_retry_count,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires ZENPROXY_TEST_DATABASE_URL pointing at a disposable PostgreSQL database"]
    fn sqlite_rows_populate_typed_postgres_columns() {
        let url = std::env::var("ZENPROXY_TEST_DATABASE_URL")
            .expect("ZENPROXY_TEST_DATABASE_URL is required for this ignored test");
        let mut pg = Client::connect(&url, NoTls).unwrap();
        init_schema(&mut pg).unwrap();
        let sqlite = Connection::open_in_memory().unwrap();
        sqlite
            .execute_batch(
                "CREATE TABLE subscriptions (
                    id TEXT, name TEXT, sub_type TEXT, url TEXT, content TEXT,
                    proxy_count INTEGER, created_at TEXT, updated_at TEXT
                 );
                 CREATE TABLE proxies (
                    id TEXT, subscription_id TEXT, name TEXT, proxy_type TEXT,
                    server TEXT, port INTEGER, config_json TEXT, is_valid INTEGER,
                    local_port INTEGER, error_count INTEGER, last_error TEXT,
                    last_validated TEXT, created_at TEXT, updated_at TEXT
                 );
                 CREATE TABLE proxy_quality (
                    proxy_id TEXT, ip_address TEXT, country TEXT, ip_type TEXT,
                    is_residential INTEGER, chatgpt_accessible INTEGER,
                    google_accessible INTEGER, risk_score REAL, risk_level TEXT,
                    extra_json TEXT, checked_at TEXT
                 );
                 CREATE TABLE users (
                    id TEXT, username TEXT, name TEXT, avatar_template TEXT,
                    active INTEGER, trust_level INTEGER, silenced INTEGER,
                    is_banned INTEGER, api_key TEXT, created_at TEXT, updated_at TEXT
                 );
                 CREATE TABLE sessions (
                    id TEXT, user_id TEXT, created_at TEXT, expires_at TEXT
                 );",
            )
            .unwrap();
        let suffix = uuid::Uuid::new_v4().to_string();
        let sub_id = format!("migration-sub-{suffix}");
        let duplicate_sub_id = format!("migration-sub-duplicate-{suffix}");
        let proxy_id = format!("migration-proxy-{suffix}");
        let user_id = format!("migration-user-{suffix}");
        let session_id = format!("migration-session-{suffix}");
        let username = format!("migration-{suffix}");
        let api_key = format!("migration-key-{suffix}");
        let now = chrono::Utc::now().to_rfc3339();
        sqlite
            .execute(
                "INSERT INTO subscriptions VALUES (
                    ?1, 'migration', 'test', 'https://example.com/sub',
                    'body', 1, ?2, ?2
                 )",
                rusqlite::params![sub_id, now],
            )
            .unwrap();
        sqlite
            .execute(
                "INSERT INTO subscriptions VALUES (
                    ?1, 'migration duplicate', 'test', ' https://example.com/sub ',
                    'body', 0, ?2, ?2
                 )",
                rusqlite::params![duplicate_sub_id, now],
            )
            .unwrap();
        sqlite
            .execute(
                "INSERT INTO proxies VALUES (
                    ?1, ?2, 'node', 'trojan', 'example.com', 443,
                    '{\"type\":\"trojan\",\"server\":\"example.com\",\"server_port\":443,\"password\":\"secret\"}',
                    1, 12042, 0, NULL, ?3, ?3, ?3
                 )",
                rusqlite::params![proxy_id, sub_id, now],
            )
            .unwrap();
        sqlite
            .execute(
                "INSERT INTO proxy_quality VALUES (
                    ?1, '203.0.113.40', 'US', 'Residential', 1, 1, 1,
                    0.1, 'Low',
                    '{\"schema_version\":2,\"incomplete_retry_count\":1}', ?2
                 )",
                rusqlite::params![proxy_id, now],
            )
            .unwrap();
        sqlite
            .execute(
                "INSERT INTO users VALUES (?1, ?2, NULL, NULL, 1, 0, 0, 0, ?3, ?4, ?4)",
                rusqlite::params![user_id, username, api_key, now],
            )
            .unwrap();
        sqlite
            .execute(
                "INSERT INTO sessions VALUES (?1, ?2, ?3, ?3)",
                rusqlite::params![session_id, user_id, now],
            )
            .unwrap();

        let mut tx = pg.transaction().unwrap();
        migrate_subscriptions(&sqlite, &mut tx).unwrap();
        migrate_proxies(&sqlite, &mut tx).unwrap();
        migrate_proxy_quality(&sqlite, &mut tx).unwrap();
        backfill_normalized_tables(&mut tx).unwrap();
        migrate_users(&sqlite, &mut tx).unwrap();
        migrate_sessions(&sqlite, &mut tx).unwrap();
        let row = tx
            .query_one(
                "SELECT p.definition_hash IS NOT NULL,
                        p.created_at_ts IS NOT NULL,
                        q.extra_jsonb IS NOT NULL,
                        q.schema_version,
                        q.incomplete_retry_count,
                        s.raw_proxy_count,
                        membership.definition_id IS NOT NULL,
                        health.health_state = 'healthy',
                        observed.ip_address::text = '203.0.113.40/32',
                        runtime.definition_id = membership.definition_id
                            AND runtime.local_port = 12042
                            AND runtime.binding_owner_id = p.id,
                        quality.extra_json IS NOT NULL,
                        quality.chatgpt_accessible,
                        normalized.google_accessible
                 FROM proxies p
                 JOIN proxy_quality q ON q.proxy_id = p.id
                 JOIN subscriptions s ON s.id = p.subscription_id
                 JOIN subscription_proxies membership ON membership.source_proxy_id = p.id
                 JOIN proxy_health health ON health.definition_id = membership.definition_id
                 JOIN proxy_exit observed ON observed.definition_id = membership.definition_id
                 JOIN proxy_runtime runtime ON runtime.definition_id = membership.definition_id
                 JOIN exit_quality quality ON quality.ip_address = observed.ip_address
                 JOIN normalized_proxy_quality normalized ON normalized.proxy_id = p.id
                 WHERE p.id = $1",
                &[&proxy_id],
            )
            .unwrap();
        assert!(row.get::<_, bool>(0));
        assert!(row.get::<_, bool>(1));
        assert!(row.get::<_, bool>(2));
        assert_eq!(row.get::<_, i32>(3), 2);
        assert_eq!(row.get::<_, i32>(4), 1);
        assert_eq!(row.get::<_, i32>(5), 1);
        assert!(row.get::<_, bool>(6));
        assert!(row.get::<_, bool>(7));
        assert!(row.get::<_, bool>(8));
        assert!(row.get::<_, bool>(9));
        assert!(row.get::<_, bool>(10));
        assert!(row.get::<_, bool>(11));
        assert!(row.get::<_, bool>(12));
        let claimed_url_count: i64 = tx
            .query_one(
                "SELECT COUNT(*) FILTER (WHERE url IS NOT NULL)
                 FROM subscriptions WHERE id = ANY($1::text[])",
                &[&vec![sub_id.clone(), duplicate_sub_id.clone()]],
            )
            .unwrap()
            .get(0);
        assert_eq!(claimed_url_count, 1);
        tx.rollback().unwrap();
    }
}
