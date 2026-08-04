use serde::Deserialize;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub singbox: SingboxConfig,
    pub database: DatabaseConfig,
    pub validation: ValidationConfig,
    pub quality: QualityConfig,
    pub oauth: OAuthConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub subscription: SubscriptionConfig,
    #[serde(default)]
    pub proxy_listener: Vec<ProxyListenerConfig>,
    #[serde(default)]
    pub proxy_access: ProxyAccessConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub admin_password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub required_guild_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SingboxConfig {
    pub binary_path: PathBuf,
    pub config_path: PathBuf,
    pub base_port: u16,
    /// Binding/port budget for live sing-box outbounds, not the total proxy inventory cap.
    #[serde(default = "default_max_proxies")]
    pub max_proxies: usize,
    #[serde(default = "default_prebound_proxies")]
    pub prebound_proxies: usize,
    #[serde(default = "default_binding_idle_secs")]
    pub binding_idle_secs: u64,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default = "default_watchdog_interval_secs")]
    pub watchdog_interval_secs: u64,
    #[serde(default)]
    pub restart_interval_mins: u64,
    /// Restart sing-box when its RSS exceeds this many MiB. Set 0 to disable.
    #[serde(default = "default_memory_restart_mb")]
    pub memory_restart_mb: u64,
    pub api_secret: Option<String>,
}

fn default_max_proxies() -> usize {
    20000
}

fn default_prebound_proxies() -> usize {
    200
}

fn default_binding_idle_secs() -> u64 {
    300
}

fn default_api_port() -> u16 {
    9090
}

fn default_watchdog_interval_secs() -> u64 {
    60
}

fn default_memory_restart_mb() -> u64 {
    3072
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidationConfig {
    pub url: String,
    /// Optional second probe used when the primary probe cannot be reached.
    #[serde(default)]
    pub fallback_url: Option<String>,
    pub timeout_secs: u64,
    pub concurrency: usize,
    pub interval_mins: u64,
    pub error_threshold: u32,
    #[serde(default = "default_validation_max_rounds")]
    pub max_rounds_per_run: usize,
    #[serde(default = "default_retry_invalid_per_run")]
    pub retry_invalid_per_run: usize,
    /// How many port slots to reserve for validation/quality-check per round.
    /// The rest stay with Valid proxies serving users. Default 30.
    #[serde(default = "default_validation_batch")]
    pub batch_size: usize,
    /// Re-check previously valid proxies after this many hours. Set 0 to disable.
    #[serde(default = "default_valid_recheck_hours")]
    pub valid_recheck_hours: u64,
    /// Share of each scheduling batch reserved for never-tested proxies.
    #[serde(default = "default_new_proxy_percent")]
    pub new_proxy_percent: u8,
    /// Share reserved for periodically rechecking valid proxies.
    #[serde(default = "default_valid_recheck_percent")]
    pub valid_recheck_percent: u8,
    /// Share reserved for cooled-down invalid proxies.
    #[serde(default = "default_invalid_retry_percent")]
    pub invalid_retry_percent: u8,
    /// Consecutive binding failures tolerated before a proxy is removed.
    #[serde(default = "default_binding_failure_threshold")]
    pub binding_failure_threshold: u32,
}

fn default_validation_max_rounds() -> usize {
    100
}

fn default_retry_invalid_per_run() -> usize {
    60
}

fn default_validation_batch() -> usize {
    30
}

fn default_valid_recheck_hours() -> u64 {
    24
}

fn default_new_proxy_percent() -> u8 {
    70
}

fn default_valid_recheck_percent() -> u8 {
    20
}

fn default_invalid_retry_percent() -> u8 {
    10
}

fn default_binding_failure_threshold() -> u32 {
    3
}

#[derive(Debug, Clone, Deserialize)]
pub struct QualityConfig {
    pub interval_mins: u64,
    pub concurrency: usize,
    /// Re-check capability and exit-IP metadata after this many hours.
    #[serde(default = "default_quality_stale_hours")]
    pub stale_hours: u64,
    /// Maximum number of proxies checked in one catch-up batch.
    #[serde(default = "default_quality_max_checks_per_run")]
    pub max_checks_per_run: usize,
}

fn default_quality_stale_hours() -> u64 {
    24
}

fn default_quality_max_checks_per_run() -> usize {
    200
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    #[serde(default = "default_relay_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_relay_timeout_secs(),
        }
    }
}

fn default_relay_timeout_secs() -> u64 {
    600
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubscriptionConfig {
    /// Password embedded in client subscription URLs. Older configurations
    /// without this field fall back to the admin password during migration.
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub auto_refresh_interval_mins: u64, // legacy/global default for subscriptions without explicit interval
    #[serde(default = "default_orphaned_valid_grace_hours")]
    pub orphaned_valid_grace_hours: u64,
    #[serde(default = "default_export_cache_secs")]
    pub export_cache_secs: u64,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            password: None,
            auto_refresh_interval_mins: 0,
            orphaned_valid_grace_hours: default_orphaned_valid_grace_hours(),
            export_cache_secs: default_export_cache_secs(),
        }
    }
}

fn default_orphaned_valid_grace_hours() -> u64 {
    24
}

fn default_export_cache_secs() -> u64 {
    60
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProxyListenerConfig {
    #[serde(default)]
    pub name: String,
    pub listen: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyAccessConfig {
    /// static: configured listener credential only; hybrid: static + accounts;
    /// accounts/database: database accounts only.
    #[serde(default = "default_proxy_auth_mode")]
    pub auth_mode: String,
    #[serde(default)]
    pub credential_secret: String,
    #[serde(default)]
    pub public_host: String,
    #[serde(default)]
    pub public_port: u16,
}

impl Default for ProxyAccessConfig {
    fn default() -> Self {
        Self {
            auth_mode: default_proxy_auth_mode(),
            credential_secret: String::new(),
            public_host: String::new(),
            public_port: 0,
        }
    }
}

fn default_proxy_auth_mode() -> String {
    "static".to_string()
}

impl ProxyAccessConfig {
    pub fn static_enabled(&self) -> bool {
        matches!(self.auth_mode.as_str(), "static" | "hybrid")
    }

    pub fn accounts_enabled(&self) -> bool {
        matches!(self.auth_mode.as_str(), "hybrid" | "accounts" | "database")
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string("config.toml")
            .unwrap_or_else(|_| include_str!("../config.toml.example").to_string());
        let mut config: AppConfig = toml::from_str(&content)?;
        config.apply_env_overrides()?;
        Ok(config)
    }

    fn apply_env_overrides(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        set_string_from_env(&mut self.server.host, "ZENPROXY_SERVER_HOST");
        set_u16_from_env(&mut self.server.port, "ZENPROXY_SERVER_PORT")?;
        set_string_from_env(&mut self.server.admin_password, "ZENPROXY_ADMIN_PASSWORD");
        set_string_from_env(&mut self.proxy_access.auth_mode, "ZENPROXY_PROXY_AUTH_MODE");
        set_string_from_env(
            &mut self.proxy_access.credential_secret,
            "ZENPROXY_PROXY_CREDENTIAL_SECRET",
        );
        set_string_from_env(
            &mut self.proxy_access.public_host,
            "ZENPROXY_PUBLIC_PROXY_HOST",
        );
        set_u16_from_env(
            &mut self.proxy_access.public_port,
            "ZENPROXY_PUBLIC_PROXY_PORT",
        )?;
        if let Some(value) = env_value("ZENPROXY_SUBSCRIPTION_PASSWORD") {
            self.subscription.password = Some(value);
        }

        set_string_from_env(&mut self.database.url, "ZENPROXY_DATABASE_URL");

        set_string_from_env(&mut self.oauth.client_id, "ZENPROXY_OAUTH_CLIENT_ID");
        set_string_from_env(
            &mut self.oauth.client_secret,
            "ZENPROXY_OAUTH_CLIENT_SECRET",
        );
        set_string_from_env(&mut self.oauth.redirect_uri, "ZENPROXY_OAUTH_REDIRECT_URI");
        set_string_from_env(
            &mut self.oauth.required_guild_id,
            "ZENPROXY_OAUTH_REQUIRED_GUILD_ID",
        );

        // Proxy listeners from env: ZENPROXY_PROXY_LISTENER or ZENPROXY_PROXY_LISTENER_1..N
        let mut env_listeners = Vec::new();
        if let Some(val) = env_value("ZENPROXY_PROXY_LISTENER") {
            if let Some(cfg) = parse_listener_uri(&val, "env") {
                env_listeners.push(cfg);
            }
        }
        for i in 1..=10 {
            let key = format!("ZENPROXY_PROXY_LISTENER_{i}");
            if let Some(val) = env_value(&key) {
                if let Some(cfg) = parse_listener_uri(&val, &format!("env-{i}")) {
                    env_listeners.push(cfg);
                }
            }
        }
        if !env_listeners.is_empty() {
            self.proxy_listener = env_listeners;
        }

        if !matches!(
            self.proxy_access.auth_mode.as_str(),
            "static" | "hybrid" | "accounts" | "database"
        ) {
            return Err(format!(
                "invalid ZENPROXY_PROXY_AUTH_MODE: {}",
                self.proxy_access.auth_mode
            )
            .into());
        }
        if self.proxy_access.accounts_enabled()
            && self.proxy_access.credential_secret.as_bytes().len() < 32
        {
            return Err(
                "ZENPROXY_PROXY_CREDENTIAL_SECRET must contain at least 32 bytes when account authentication is enabled"
                    .into(),
            );
        }

        Ok(())
    }

    pub fn subscription_password(&self) -> &str {
        self.subscription
            .password
            .as_deref()
            .filter(|password| !password.is_empty())
            .unwrap_or(&self.server.admin_password)
    }
}

fn env_value(key: &str) -> Option<String> {
    env::var_os(key).map(|value| value.to_string_lossy().into_owned())
}

fn set_string_from_env(target: &mut String, key: &str) {
    if let Some(value) = env_value(key) {
        *target = value;
    }
}

fn set_u16_from_env(target: &mut u16, key: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(value) = env_value(key) {
        *target = value.parse()?;
    }
    Ok(())
}

/// Parse `user:pass@host:port` into a `ProxyListenerConfig`.
fn parse_listener_uri(uri: &str, default_name: &str) -> Option<ProxyListenerConfig> {
    let (creds, listen) = uri.rsplit_once('@')?;
    let (username, password) = creds.split_once(':')?;
    if username.is_empty() || password.is_empty() || listen.is_empty() {
        return None;
    }
    Some(ProxyListenerConfig {
        name: default_name.to_string(),
        listen: listen.to_string(),
        username: username.to_string(),
        password: password.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::AppConfig;

    #[test]
    fn reads_independent_subscription_password() {
        let config: AppConfig = toml::from_str(include_str!("../config.toml.example")).unwrap();

        assert_eq!(
            config.subscription_password(),
            "change-subscription-password"
        );
        assert_ne!(config.subscription_password(), config.server.admin_password);
    }

    #[test]
    fn old_config_falls_back_to_admin_password() {
        let source = include_str!("../config.toml.example")
            .replace("password = \"change-subscription-password\"\n", "");
        let config: AppConfig = toml::from_str(&source).unwrap();

        assert_eq!(config.subscription_password(), "change-me");
    }
}
