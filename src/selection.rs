use crate::db::{Database, ProxyQuality, ProxyRow};
use crate::pool::manager::{PoolProxy, ProxyFilter, ProxyPool};
use crate::AppState;
use rand::seq::index;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CAP_CHATGPT: u8 = 1;
const CAP_GOOGLE: u8 = 1 << 1;
const CAP_RESIDENTIAL: u8 = 1 << 2;
const RELAY_FAILURE_COOLDOWN_SECS: i64 = 300;
pub const SNAPSHOT_REFRESH_SECS: u64 = 30;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct BucketKey {
    country: Option<String>,
    proxy_type: Option<String>,
    required_capabilities: u8,
}

#[derive(Clone)]
struct SelectionMember {
    proxy: Arc<PoolProxy>,
    definition_key: Arc<str>,
    risk_score: f64,
    rank: (u8, u32),
}

struct ExitGroup {
    exit_ip: Arc<str>,
    min_risk_score: f64,
    members: Vec<Arc<SelectionMember>>,
}

struct SelectionTier {
    groups: Vec<ExitGroup>,
}

#[derive(Default)]
struct SelectionBucket {
    tiers: Vec<SelectionTier>,
}

/// Immutable, filter-aware selection index. Every bucket contains at most one
/// group per measured exit IP and every group retains alternative proxy
/// definitions for failover. Full outbound definitions live behind `Arc`, so
/// the data-plane path clones only the handful of selected results.
pub struct SelectionSnapshot {
    buckets: HashMap<BucketKey, SelectionBucket>,
    proxy_count: usize,
    exit_count: usize,
}

impl SelectionSnapshot {
    pub fn load(db: &Database) -> Result<Self, postgres::Error> {
        db.get_selectable_proxy_records().map(Self::build)
    }

    pub fn build(records: Vec<(ProxyRow, Option<ProxyQuality>)>) -> Self {
        let cutoff = chrono::Utc::now()
            - chrono::Duration::seconds(RELAY_FAILURE_COOLDOWN_SECS);
        let mut staging: HashMap<
            BucketKey,
            HashMap<String, Vec<Arc<SelectionMember>>>,
        > = HashMap::new();
        let mut all_exits = HashSet::new();
        let mut proxy_count = 0usize;

        for (row, quality) in records {
            let Some(quality) = quality else {
                continue;
            };
            let Some(exit_ip) = quality
                .ip_address
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
            else {
                continue;
            };

            let definition_key =
                Arc::<str>::from(crate::api::subscription::proxy_row_definition_key(&row));
            let rank = selection_rank(
                row.error_count.max(0) as u32,
                row.last_validated.as_deref(),
                &cutoff,
            );
            let country = quality
                .country
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_ascii_uppercase);
            let proxy_type = Some(row.proxy_type.to_ascii_lowercase());
            let capability_mask = capability_mask(&quality);
            let risk_score = if quality.risk_score.is_finite() {
                quality.risk_score
            } else {
                1.0
            };
            let proxy = Arc::new(ProxyPool::from_db_parts(row, Some(quality)));
            let member = Arc::new(SelectionMember {
                proxy,
                definition_key,
                risk_score,
                rank,
            });

            let mut dimensions = HashSet::new();
            dimensions.insert((None, None));
            dimensions.insert((country.clone(), None));
            dimensions.insert((None, proxy_type.clone()));
            dimensions.insert((country, proxy_type));

            for (country, proxy_type) in dimensions {
                for required_capabilities in capability_subsets(capability_mask) {
                    let key = BucketKey {
                        country: country.clone(),
                        proxy_type: proxy_type.clone(),
                        required_capabilities,
                    };
                    staging
                        .entry(key)
                        .or_default()
                        .entry(exit_ip.clone())
                        .or_default()
                        .push(member.clone());
                }
            }

            proxy_count += 1;
            all_exits.insert(exit_ip);
        }

        let buckets = staging
            .into_iter()
            .map(|(key, exits)| (key, finalize_bucket(exits)))
            .collect();

        Self {
            buckets,
            proxy_count,
            exit_count: all_exits.len(),
        }
    }

    pub fn pick(&self, filter: &ProxyFilter, count: usize, state: &AppState) -> Vec<PoolProxy> {
        let now = Instant::now();
        self.pick_with(filter, count, &|definition| {
            definition_is_excluded(state, definition, now)
        })
    }

    fn pick_with<F>(&self, filter: &ProxyFilter, count: usize, is_excluded: &F) -> Vec<PoolProxy>
    where
        F: Fn(&str) -> bool,
    {
        if count == 0 || filter.risk_max.is_some_and(|value| !value.is_finite()) {
            return Vec::new();
        }
        let key = BucketKey {
            country: filter
                .country
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_ascii_uppercase),
            proxy_type: filter
                .proxy_type
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_ascii_lowercase),
            required_capabilities: required_capability_mask(filter),
        };
        let Some(bucket) = self.buckets.get(&key) else {
            return Vec::new();
        };

        let mut selected = Vec::with_capacity(count);
        let mut selected_exits = HashSet::with_capacity(count);
        let mut rng = rand::thread_rng();

        for tier in &bucket.tiers {
            if selected.len() >= count {
                break;
            }
            let eligible = eligible_group_count(&tier.groups, filter.risk_max);
            if eligible == 0 {
                continue;
            }

            // The common path samples only a small multiple of the requested
            // count. A linear fallback is used only when a snapshot has many
            // newly excluded definitions or the caller requests a large set.
            let remaining = count - selected.len();
            let sample_len = eligible.min(remaining.saturating_mul(4).saturating_add(16));
            let sampled = index::sample(&mut rng, eligible, sample_len).into_vec();
            for group_index in &sampled {
                let group = &tier.groups[*group_index];
                if let Some(proxy) = select_group_member(group, filter.risk_max, is_excluded) {
                    if selected_exits.insert(group.exit_ip.clone()) {
                        selected.push(proxy);
                        if selected.len() >= count {
                            break;
                        }
                    }
                }
            }

            if selected.len() < count && sample_len < eligible {
                let sampled: HashSet<_> = sampled.into_iter().collect();
                for (group_index, group) in tier.groups[..eligible].iter().enumerate() {
                    if sampled.contains(&group_index) {
                        continue;
                    }
                    if let Some(proxy) = select_group_member(group, filter.risk_max, is_excluded) {
                        if selected_exits.insert(group.exit_ip.clone()) {
                            selected.push(proxy);
                            if selected.len() >= count {
                                break;
                            }
                        }
                    }
                }
            }
        }

        selected
    }

    pub fn proxy_count(&self) -> usize {
        self.proxy_count
    }

    pub fn exit_count(&self) -> usize {
        self.exit_count
    }
}

pub fn rebuild(state: &AppState) -> Result<(), postgres::Error> {
    let snapshot = SelectionSnapshot::load(&state.db)?;
    tracing::info!(
        "Rebuilt selection snapshot: {} selectable definitions across {} exits",
        snapshot.proxy_count(),
        snapshot.exit_count()
    );
    state.selection_snapshot.store(Arc::new(snapshot));
    let now = Instant::now();
    state
        .selection_unavailable_definitions
        .retain(|_, excluded_until| *excluded_until > now);
    Ok(())
}

pub fn exclude_definition(state: &AppState, proxy: &PoolProxy) {
    let definition = crate::api::subscription::outbound_definition_key(
        &proxy.proxy_type,
        &proxy.server,
        proxy.port,
        &proxy.singbox_outbound,
    );
    state
        .selection_unavailable_definitions
        .insert(
            definition,
            Instant::now() + Duration::from_secs(RELAY_FAILURE_COOLDOWN_SECS as u64),
        );
}

fn definition_is_excluded(state: &AppState, definition: &str, now: Instant) -> bool {
    let active = state
        .selection_unavailable_definitions
        .get(definition)
        .is_some_and(|expires_at| *expires_at > now);
    if !active {
        state.selection_unavailable_definitions.remove(definition);
    }
    active
}

fn finalize_bucket(
    exits: HashMap<String, Vec<Arc<SelectionMember>>>,
) -> SelectionBucket {
    let mut tiers: BTreeMap<(u8, u32), Vec<ExitGroup>> = BTreeMap::new();
    for (exit_ip, mut members) in exits {
        members.sort_by(|left, right| {
            left.rank
                .cmp(&right.rank)
                .then_with(|| left.proxy.id.cmp(&right.proxy.id))
        });
        let mut definitions = HashSet::new();
        members.retain(|member| definitions.insert(member.definition_key.clone()));
        let Some(best) = members.first() else {
            continue;
        };
        let rank = best.rank;
        let min_risk_score = members
            .iter()
            .map(|member| member.risk_score)
            .fold(f64::INFINITY, f64::min);
        tiers.entry(rank).or_default().push(ExitGroup {
            exit_ip: Arc::from(exit_ip),
            min_risk_score,
            members,
        });
    }

    SelectionBucket {
        tiers: tiers
            .into_values()
            .map(|mut groups| {
                groups.sort_by(|left, right| {
                    left.min_risk_score.total_cmp(&right.min_risk_score)
                });
                SelectionTier { groups }
            })
            .collect(),
    }
}

fn select_group_member<F>(
    group: &ExitGroup,
    risk_max: Option<f64>,
    is_excluded: &F,
) -> Option<PoolProxy>
where
    F: Fn(&str) -> bool,
{
    group.members.iter().find_map(|member| {
        if risk_max.is_some_and(|max| member.risk_score > max)
            || is_excluded(member.definition_key.as_ref())
        {
            return None;
        }
        Some(member.proxy.as_ref().clone())
    })
}

fn eligible_group_count(groups: &[ExitGroup], risk_max: Option<f64>) -> usize {
    match risk_max {
        Some(max) => groups.partition_point(|group| group.min_risk_score <= max),
        None => groups.len(),
    }
}

fn capability_mask(quality: &ProxyQuality) -> u8 {
    (u8::from(quality.chatgpt_accessible) * CAP_CHATGPT)
        | (u8::from(quality.google_accessible) * CAP_GOOGLE)
        | (u8::from(quality.is_residential) * CAP_RESIDENTIAL)
}

fn required_capability_mask(filter: &ProxyFilter) -> u8 {
    (u8::from(filter.chatgpt) * CAP_CHATGPT)
        | (u8::from(filter.google) * CAP_GOOGLE)
        | (u8::from(filter.residential) * CAP_RESIDENTIAL)
}

fn capability_subsets(mask: u8) -> Vec<u8> {
    let mut subsets = Vec::new();
    let mut subset = mask;
    loop {
        subsets.push(subset);
        if subset == 0 {
            break;
        }
        subset = (subset - 1) & mask;
    }
    subsets
}

fn selection_rank(
    error_count: u32,
    last_validated: Option<&str>,
    cooldown_before: &chrono::DateTime<chrono::Utc>,
) -> (u8, u32) {
    let class = if error_count == 0 {
        0
    } else if last_validated
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|checked| checked.with_timezone(&chrono::Utc) <= *cooldown_before)
    {
        1
    } else {
        2
    };
    (class, error_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, proxy_type: &str, password: &str) -> ProxyRow {
        let now = chrono::Utc::now().to_rfc3339();
        ProxyRow {
            id: id.into(),
            subscription_id: "sub-1".into(),
            name: id.into(),
            proxy_type: proxy_type.into(),
            server: "example.com".into(),
            port: 443,
            config_json: serde_json::json!({
                "type": proxy_type,
                "server": "example.com",
                "server_port": 443,
                "password": password,
                "tag": id
            })
            .to_string(),
            is_valid: true,
            local_port: None,
            error_count: 0,
            last_error: None,
            last_validated: Some(now.clone()),
            created_at: now.clone(),
            updated_at: now,
            orphaned_at: None,
        }
    }

    fn quality(id: &str, ip: &str, country: &str, risk: f64, capabilities: u8) -> ProxyQuality {
        ProxyQuality {
            proxy_id: id.into(),
            ip_address: Some(ip.into()),
            country: Some(country.into()),
            ip_type: Some("Residential".into()),
            is_residential: capabilities & CAP_RESIDENTIAL != 0,
            chatgpt_accessible: capabilities & CAP_CHATGPT != 0,
            google_accessible: capabilities & CAP_GOOGLE != 0,
            risk_score: risk,
            risk_level: "Low".into(),
            extra_json: None,
            checked_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn capability_subsets_cover_every_query_weaker_than_the_record() {
        let subsets = capability_subsets(CAP_CHATGPT | CAP_GOOGLE | CAP_RESIDENTIAL);
        assert_eq!(subsets.len(), 8);
        assert!(subsets.contains(&0));
        assert!(subsets.contains(&(CAP_CHATGPT | CAP_GOOGLE)));
    }

    #[test]
    fn snapshot_counts_definitions_and_unique_exits() {
        let snapshot = SelectionSnapshot::build(vec![
            (
                row("a", "vmess", "a"),
                Some(quality("a", "203.0.113.1", "US", 0.1, CAP_GOOGLE)),
            ),
            (
                row("b", "vmess", "b"),
                Some(quality("b", "203.0.113.1", "US", 0.2, CAP_GOOGLE)),
            ),
            (
                row("c", "trojan", "c"),
                Some(quality("c", "203.0.113.2", "JP", 0.3, 0)),
            ),
        ]);
        assert_eq!(snapshot.proxy_count(), 3);
        assert_eq!(snapshot.exit_count(), 2);
    }

    #[test]
    fn failure_cooldown_uses_health_check_time() {
        let cutoff = chrono::Utc::now() - chrono::Duration::minutes(5);
        let old_failure = (cutoff - chrono::Duration::minutes(1)).to_rfc3339();
        let recent_failure = (cutoff + chrono::Duration::minutes(1)).to_rfc3339();

        assert_eq!(selection_rank(1, Some(&old_failure), &cutoff).0, 1);
        assert_eq!(selection_rank(1, Some(&recent_failure), &cutoff).0, 2);
        assert_eq!(selection_rank(1, None, &cutoff).0, 2);
    }

    #[test]
    fn snapshot_deduplicates_exits_and_falls_back_to_another_definition() {
        let first = row("a", "vmess", "a");
        let first_definition = crate::api::subscription::proxy_row_definition_key(&first);
        let snapshot = SelectionSnapshot::build(vec![
            (
                first,
                Some(quality("a", "203.0.113.1", "US", 0.1, CAP_GOOGLE)),
            ),
            (
                row("b", "vmess", "b"),
                Some(quality("b", "203.0.113.1", "US", 0.2, CAP_GOOGLE)),
            ),
            (
                row("c", "trojan", "c"),
                Some(quality("c", "203.0.113.2", "JP", 0.3, 0)),
            ),
        ]);

        let all = snapshot.pick_with(&ProxyFilter::default(), 10, &|_| false);
        assert_eq!(all.len(), 2);
        let exits: HashSet<_> = all
            .iter()
            .filter_map(|proxy| proxy.quality.as_ref()?.ip_address.as_deref())
            .collect();
        assert_eq!(exits.len(), 2);

        let us_google = ProxyFilter {
            google: true,
            country: Some("us".into()),
            proxy_type: Some("VMESS".into()),
            ..Default::default()
        };
        let selected = snapshot.pick_with(&us_google, 1, &|definition| {
            definition == first_definition
        });
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, "b");
    }

    #[test]
    fn snapshot_applies_risk_threshold_without_losing_filter_semantics() {
        let snapshot = SelectionSnapshot::build(vec![
            (
                row("safe", "vmess", "a"),
                Some(quality(
                    "safe",
                    "203.0.113.1",
                    "US",
                    0.1,
                    CAP_CHATGPT | CAP_GOOGLE,
                )),
            ),
            (
                row("risky", "vmess", "b"),
                Some(quality(
                    "risky",
                    "203.0.113.2",
                    "US",
                    0.8,
                    CAP_CHATGPT | CAP_GOOGLE,
                )),
            ),
        ]);
        let filter = ProxyFilter {
            chatgpt: true,
            google: true,
            country: Some("US".into()),
            risk_max: Some(0.2),
            ..Default::default()
        };
        let selected = snapshot.pick_with(&filter, 10, &|_| false);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, "safe");
    }
}
