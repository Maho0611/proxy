use serde::Serialize;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct JobProgress {
    pub kind: String,
    pub status: String,
    pub scope: String,
    pub subscription_id: Option<String>,
    pub subscription_name: Option<String>,
    pub phase: String,
    pub total: Option<usize>,
    pub completed: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub round: usize,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub message: Option<String>,
}

impl JobProgress {
    fn idle(kind: &str) -> Self {
        Self {
            kind: kind.to_string(),
            status: "idle".to_string(),
            scope: "all".to_string(),
            subscription_id: None,
            subscription_name: None,
            phase: "idle".to_string(),
            total: None,
            completed: 0,
            succeeded: 0,
            failed: 0,
            round: 0,
            started_at: None,
            finished_at: None,
            message: None,
        }
    }
}

pub struct JobTracker {
    kind: &'static str,
    inner: Mutex<JobProgress>,
}

impl JobTracker {
    pub fn new(kind: &'static str) -> Self {
        Self {
            kind,
            inner: Mutex::new(JobProgress::idle(kind)),
        }
    }

    pub fn begin(
        &self,
        subscription_id: Option<&str>,
        subscription_name: Option<&str>,
        total: Option<usize>,
        phase: &str,
    ) {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_progress(|progress| {
            *progress = JobProgress {
                kind: self.kind.to_string(),
                status: "running".to_string(),
                scope: if subscription_id.is_some() {
                    "subscription".to_string()
                } else {
                    "all".to_string()
                },
                subscription_id: subscription_id.map(str::to_string),
                subscription_name: subscription_name.map(str::to_string),
                phase: phase.to_string(),
                total,
                completed: 0,
                succeeded: 0,
                failed: 0,
                round: 0,
                started_at: Some(now),
                finished_at: None,
                message: None,
            };
        });
    }

    pub fn set_phase(&self, phase: &str) {
        self.with_progress(|progress| progress.phase = phase.to_string());
    }

    pub fn set_round(&self, round: usize) {
        self.with_progress(|progress| progress.round = round);
    }

    pub fn set_total(&self, total: usize) {
        self.with_progress(|progress| progress.total = Some(total));
    }

    pub fn add_total(&self, count: usize) {
        self.with_progress(|progress| {
            progress.total = Some(progress.total.unwrap_or(0).saturating_add(count));
        });
    }

    pub fn advance(&self, succeeded: bool) {
        self.with_progress(|progress| {
            progress.completed = progress.completed.saturating_add(1);
            if succeeded {
                progress.succeeded = progress.succeeded.saturating_add(1);
            } else {
                progress.failed = progress.failed.saturating_add(1);
            }
        });
    }

    pub fn finish(&self, message: impl Into<String>) {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_progress(|progress| {
            progress.status = "completed".to_string();
            progress.phase = "completed".to_string();
            progress.total = Some(
                progress
                    .total
                    .unwrap_or(progress.completed)
                    .max(progress.completed),
            );
            progress.finished_at = Some(now);
            progress.message = Some(message.into());
        });
    }

    pub fn fail(&self, message: impl Into<String>) {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_progress(|progress| {
            progress.status = "failed".to_string();
            progress.phase = "failed".to_string();
            progress.finished_at = Some(now);
            progress.message = Some(message.into());
        });
    }

    pub fn snapshot(&self) -> JobProgress {
        self.with_progress(|progress| progress.clone())
    }

    fn with_progress<T>(&self, f: impl FnOnce(&mut JobProgress) -> T) -> T {
        let mut progress = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        f(&mut progress)
    }
}

#[cfg(test)]
mod tests {
    use super::JobTracker;

    #[test]
    fn tracker_records_scope_and_outcomes() {
        let tracker = JobTracker::new("validation");
        tracker.begin(Some("sub-1"), Some("source"), Some(2), "preparing");
        tracker.set_round(1);
        tracker.advance(true);
        tracker.advance(false);
        tracker.finish("done");

        let progress = tracker.snapshot();
        assert_eq!(progress.status, "completed");
        assert_eq!(progress.scope, "subscription");
        assert_eq!(progress.subscription_id.as_deref(), Some("sub-1"));
        assert_eq!(progress.completed, 2);
        assert_eq!(progress.succeeded, 1);
        assert_eq!(progress.failed, 1);
        assert_eq!(progress.total, Some(2));
        assert_eq!(progress.round, 1);
    }
}
