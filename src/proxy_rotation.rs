use crate::AppState;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

pub const MIN_INTERVAL_SECS: u64 = 1;
pub const MAX_INTERVAL_SECS: u64 = 24 * 60 * 60;
pub const MAX_SESSION_ID_LEN: usize = 32;

const MAX_ACTIVE_SESSIONS: usize = 10_000;
const MIN_IDLE_RETENTION_SECS: u64 = 5 * 60;

#[derive(Debug, Clone)]
pub struct RotationSelection {
    pub proxy_id: String,
    pub exit_ip: String,
    pub expires_at: Instant,
}

#[derive(Debug)]
pub struct RotationSessionState {
    pub selection: Option<RotationSelection>,
    pub last_seen: Instant,
    idle_retention: Duration,
}

#[derive(Debug)]
pub struct RotationSession {
    pub principal_id: String,
    pub state: Mutex<RotationSessionState>,
}

impl RotationSession {
    fn new(principal_id: String, interval_secs: u64) -> Self {
        let now = Instant::now();
        Self {
            principal_id,
            state: Mutex::new(RotationSessionState {
                selection: None,
                last_seen: now,
                idle_retention: idle_retention(interval_secs),
            }),
        }
    }
}

impl RotationSessionState {
    pub fn touch(&mut self, interval_secs: u64) {
        self.last_seen = Instant::now();
        self.idle_retention = idle_retention(interval_secs);
    }
}

pub async fn get_or_create_session(
    state: &AppState,
    key: &str,
    principal_id: &str,
    interval_secs: u64,
) -> Result<Arc<RotationSession>, String> {
    if let Some(session) = state.proxy_rotation_sessions.get(key) {
        return Ok(session.value().clone());
    }

    if state.proxy_rotation_sessions.len() >= MAX_ACTIVE_SESSIONS {
        cleanup_idle_sessions(state).await;
        if state.proxy_rotation_sessions.len() >= MAX_ACTIVE_SESSIONS {
            return Err(
                "Too many active timed-rotation sessions; reuse an existing session ID".into(),
            );
        }
    }

    let candidate = Arc::new(RotationSession::new(
        principal_id.to_string(),
        interval_secs,
    ));
    let session = state
        .proxy_rotation_sessions
        .entry(key.to_string())
        .or_insert_with(|| candidate.clone())
        .clone();
    Ok(session)
}

pub async fn cleanup_idle_sessions(state: &AppState) -> usize {
    let now = Instant::now();
    let keys: Vec<String> = state
        .proxy_rotation_sessions
        .iter()
        .map(|entry| entry.key().clone())
        .collect();
    let mut removed = 0;

    for key in keys {
        let removed_entry = state.proxy_rotation_sessions.remove_if(&key, |_, session| {
            // The map owns one Arc. Any additional strong reference means
            // a connection has already acquired this session and must be
            // allowed to touch it before cleanup can retire it.
            if Arc::strong_count(session) != 1 {
                return false;
            }
            let Ok(session_state) = session.state.try_lock() else {
                return false;
            };
            now.duration_since(session_state.last_seen) >= session_state.idle_retention
        });
        if removed_entry.is_some() {
            removed += 1;
        }
    }

    removed
}

pub fn remove_principal_sessions(state: &AppState, principal_id: &str) -> usize {
    let before = state.proxy_rotation_sessions.len();
    state
        .proxy_rotation_sessions
        .retain(|_, session| session.principal_id != principal_id);
    before.saturating_sub(state.proxy_rotation_sessions.len())
}

pub fn valid_session_id(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id.len() <= MAX_SESSION_ID_LEN
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn idle_retention(interval_secs: u64) -> Duration {
    Duration::from_secs(interval_secs.saturating_mul(2).max(MIN_IDLE_RETENTION_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_is_safe_for_username_suffixes() {
        assert!(valid_session_id("crawler_01"));
        assert!(valid_session_id("A"));
        assert!(!valid_session_id(""));
        assert!(!valid_session_id("contains-hyphen"));
        assert!(!valid_session_id("contains space"));
        assert!(!valid_session_id(&"a".repeat(MAX_SESSION_ID_LEN + 1)));
    }

    #[test]
    fn idle_retention_has_a_floor_and_scales_with_long_intervals() {
        assert_eq!(idle_retention(1), Duration::from_secs(300));
        assert_eq!(idle_retention(600), Duration::from_secs(1200));
    }
}
