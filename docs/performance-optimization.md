# 性能与正确性优化方案（修订版）

在第一版（纯性能视角）基础上，合入 GPT 报告的发现后重新排序。
**最重要的变化：优先级顺序改了。** 第一版把连接池放在 P0 第一位，本版把它降到第三阶段——
理由见 §6「关于连接池顺序的分歧」。

所有结论均已对照代码核实，行号可点。参考规模（`config.toml.example`）：
`max_proxies=20000`、`validation.concurrency=200`、`batch_size=300`、`max_rounds_per_run=20`、
`prebound_proxies=500`、`quality.concurrency=10`、`max_checks_per_run=200`、`error_threshold=10`。

> **2026-08-05 落地审核状态：** S0–S5 已按本文主线实现；正文中的旧代码片段保留作
> 问题基线，不代表当前实现。最终审核额外修正了旧 PostgreSQL 原地升级的哈希回填、
> 定向绑定逐条读库、绑定失败误删除以及质量租约重复领取。本文的收益数字仍是估计，
> 在生产规模压测前不作为已实现的加速比承诺。

---

## 0. 重新排序的依据

第一版只按"哪里慢"排序，漏了两件更重要的事：

1. **有两个正确性缺陷正在持续制造额外工作量。** 验活误杀会把能用的代理 `DELETE` 掉，
   订阅刷新时它们又作为 untested 回来重新验活——这是一个自我供能的空转循环。
   不先修它，后面所有吞吐优化都在给一个漏水的桶加压。
2. **数据平面（用户连接）和控制平面（验活/质检）的优化价值不对等。**
   每个客户端 TCP 连接都会触发一次全表 `ORDER BY RANDOM()`，且持有全局 DB 锁。
   这是用户直接感知的延迟，优先级高于后台任务吞吐。

所以新顺序是：**止血 → 数据平面 → 控制平面吞吐 → schema → 调度模型 → 数据模型**。

---

## S0　先止血：两个正确性缺陷

### S0-1　验活误杀，并且会真的删库

`src/pool/validator.rs:429-435`
```rust
let result = match validate_with_fallback(&proxy_addr, &url, fallback_url.as_deref(), timeout).await {
    Ok(()) => detect_exit_ip(&proxy_addr, timeout).await,   // 探活成功后再查出口 IP
    Err(error) => Err(error),
};
match result {
    Ok(exit_ip) => { /* 标记 valid */ }
    Err(e) => {
        // 探活成功但出口 IP 查询失败，也走到这里
        state.db.update_exact_duplicate_validation(&proxy_id, false, Some(&e), None)
```

**代理通过了 204 探活、网络明确可用，但因为出口 IP 查询失败被判为 invalid，且 `error_count + 1`。**

这不只是标记错误。`src/db.rs:2193-2206`：
```rust
pub fn cleanup_high_error_proxies(&self, threshold: u32) -> Result<usize, postgres::Error> {
    // ...
    let count = conn.execute("DELETE FROM proxies WHERE error_count >= $1", &[&threshold])?;
```
`error_threshold = 10`，每次验活运行结束都会调用（`validator.rs:190`）。
**连续 10 次出口 IP 查询失败 → 能用的代理被物理删除。**

而 `detect_exit_ip`（`validator.rs:539-558`）要求 Cloudflare trace **和** ipify 都失败才算失败——
这看起来很难，但实际很容易同时发生：

- 大量代理共享同一个出口 IP（`get_stats` 里 `COUNT(DISTINCT q.ip_address)` 与 `COUNT(*)` 的差值就是证据），
  ipify 按源 IP 限流，一批并发验活很容易把它打到 429。
- Cloudflare `cdn-cgi/trace` 在部分地区/机房被拦或返回非预期内容。
- `concurrency = 200` 会把这两个第三方端点同时打满。

删除之后代理不会消失——订阅刷新时它作为 untested 重新插入，再次进入完整验活流程。
**这是一个持续消耗验活预算的空转循环，而且它伪装成"代理质量差"。**

**修法**：存活与出口 IP 是两个独立结论，不能耦合。
```rust
// 探活成功 = valid，出口 IP 只是附加信息
match validate_with_fallback(...).await {
    Ok(()) => {
        let exit_ip = detect_exit_ip(&proxy_addr, timeout).await.ok();  // 失败不影响判定
        record_alive(&proxy_id, exit_ip);      // exit_ip 为 None 时只更新健康状态
    }
    Err(e) => record_dead(&proxy_id, &e),
}
```
出口 IP 缺失应表达为"存活但出口未测量"，由质检阶段补齐，而不是判死。

> 与第一版的冲突：第一版 P0-11 建议"把 `cdn-cgi/trace` 当作主探测，一次请求同时拿存活和出口 IP"。
> **在修好 S0-1 之前不要做这个改动**——那会让 trace 的可用性直接决定存活判定，把误杀放大。
> 正确的组合顺序见 S2-5。

顺带一并修：`cleanup_high_error_proxies` 直接 `DELETE` 过于激进，
建议改为标记下线（`health_state = 'unhealthy'`）并保留记录，配合 S4 的状态机。
删除记录的唯一后果就是下次刷新再插一遍。

### S0-2　解锁检测的错误被当作"不可用"固化 72 小时

`src/quality/unlock.rs:102-103`
```rust
let google_accessible  = google.available  == Some(true);
let chatgpt_accessible = chatgpt.available == Some(true);
```
`UnlockCheck::error()` 产生 `available: None`（`unlock.rs:61-68`），
`None == Some(true)` 为 `false` → **网络错误和"明确被封"塌缩成同一个 `false`。**
落库的两列是 `BOOLEAN NOT NULL DEFAULT FALSE`（`db.rs:320-322`）。

> 修正 GPT 报告的一处表述：**原始信息其实没有丢。**
> `UnlockCheck::as_json`（`unlock.rs:71-78`）保留了 `"status": "error"`、`"available": null`，
> 完整写进了 `extra_json.checks.<service>`。丢信息的是**被提升到列的那两个布尔值**。

真正的问题在下一步。`src/quality/checker.rs:468-473`
```rust
fn quality_is_incomplete(q: &ProxyQualityInfo) -> bool {
    q.country.is_none() || q.ip_type.is_none() || q.ip_address.is_none()
        || q.risk_level == "Unknown"
    // ← 完全没有检查解锁结果是否是 error
}
```
所以：**一次解锁检测全军覆没（全是 error）的代理，会被记为"数据完整"，
两个布尔值定成 `false`，然后 `stale_hours = 72` 内不再复检。**

后果是这两列被下游当作事实使用：
- `proxy_listener` 的 `filter.chatgpt` / `filter.google`（`pool/manager.rs:270-283`）
- `fixed_proxy_slots.chatgpt` / `.google`（`db.rs:362-382`）

→ 一次瞬时网络抖动，会让一批好代理在 3 天内从"支持 ChatGPT"的可用池里消失。

**修法**：
1. `quality_is_incomplete` 增加判断：`extra_json.checks` 里关键服务是 `"error"` 时视为不完整，
   走已有的 `MAX_INCOMPLETE_RETRIES` 重试预算。
2. 每个服务落库 `available/unavailable/error` 三态 + `checked_at`，不再只存布尔。
   过渡期可以保留布尔列（下游不用改），但补一列 `unlock_json jsonb` 存三态明细，
   下游筛选改成 `unlock_json->'google'->>'status' = 'available'`。

---

## S1　数据平面：每个连接一次全表随机排序

**GPT 报告指出的这一条，第一版完全漏了，而它可能是最该先做的性能项。**

调用链：
`proxy_listener.rs:374` / `proxy_listener.rs:572`
→ `fetch.rs:247` `pick_random_valid_proxies`（**无任何缓存**）
→ `db.rs:1173` `get_random_valid_proxy_records`

`src/db.rs:1197-1213` 每个新客户端连接都会执行：
```sql
SELECT ... FROM (
    SELECT DISTINCT ON (q.ip_address) ...          -- ① 全量 valid∩quality 排序去重
    FROM proxies p JOIN proxy_quality q ON q.proxy_id = p.id
    WHERE <filter>
    ORDER BY q.ip_address, p.error_count ASC, p.last_validated DESC NULLS LAST, ...
) p
ORDER BY <case>, p.error_count ASC, RANDOM()       -- ② 再一次全量物化 + 排序
LIMIT $n                                            -- 最后只取 3-4 条
```

两次全量排序：`DISTINCT ON` 必须排序全部匹配行；`RANDOM()` 让任何索引都失效、
必须物化整个去重后集合才能选出 `LIMIT` 3-4 条。**而且全程持有那把全局 DB 锁。**

也就是说：每个 TCP 连接的建立延迟里，包含一次 O(N log N) 的全表排序，并且串行。
2 万节点规模下这是数据平面的硬上限。

已有的内存路径不能直接用：`pool.pick_random`（`pool/manager.rs:315-322`）
```rust
pub fn pick_random(&self, filter: &ProxyFilter, count: usize) -> Vec<PoolProxy> {
    let mut candidates = self.filter_proxies(filter);   // 深拷贝整个候选集（含 config JSON）
    candidates.shuffle(&mut rng);                        // O(n) 洗牌只为取 3-4 条
```
它同样是 O(n)，还多了每个 `PoolProxy` 的深拷贝，且**没有按出口 IP 去重**——
而 `DISTINCT ON (q.ip_address)` 是这个查询的核心语义（同出口 IP 只算一个可选出口），不能丢。

**方案：预计算的选择快照。**

```rust
/// 轻量句柄——不含 config_json，只有选择和连接需要的字段
#[derive(Clone, Copy)]
struct Candidate { idx: u32, local_port: Option<u16>, error_count: u16 }

pub struct SelectionSnapshot {
    /// 按 (country, chatgpt, google, residential, proxy_type) 分桶，
    /// 每桶内已按出口 IP 去重、已按 error_count 分层
    buckets: HashMap<FilterKey, Vec<Candidate>>,
    ids: Vec<Arc<str>>,        // idx → proxy id
    built_at: Instant,
}
```
- 取样：桶内 `rand::seq::index::sample` 直接 O(count)，不排序、不洗牌、不克隆。
- 重建：验活/质检批次结束后（已有 `invalidate_stats_cache` / `invalidate_subscription_export_cache`
  的调用点，`validator.rs:203-204`、`checker.rs:169-170`）顺带 rebuild；
  另加一个兜底 TTL（如 30s）防止漏失效。
- 用 `arc_swap::ArcSwap<SelectionSnapshot>` 存放，读路径零锁零拷贝。
- 出口 IP 去重在**构建时**做一次，而不是每个连接做一次——这是最大的收益来源。

`RELAY_FAILURE_COOLDOWN_SECS` 那个"最近失败降权"逻辑（`db.rs:3312-3329`）
在快照里表达为分层桶（`error_count == 0` / 冷却中 / 其他），取样时按层优先，语义等价。

代价：快照重建是 O(N)，但频率从"每连接"降到"每验活批次"。

---

## S2　控制平面吞吐

### S2-1　验活/质检结果批量写回

`validator.rs:437-521`：200 个并发任务，每个拿到探测结果就立刻
`update_exact_duplicate_validation`（内部 2 次 SELECT + 事务内逐 id UPDATE），
失败路径还要逐 id `delete_proxy_if_orphaned`（`validator.rs:501-510`）。
全部撞同一把 Mutex。

改成探测与落库分离：
```rust
let (tx, mut rx) = tokio::sync::mpsc::channel::<ProbeOutcome>(1024);

let writer = tokio::spawn(async move {
    let mut buf = Vec::with_capacity(500);
    let mut ticker = tokio::time::interval(Duration::from_secs(2));   // 防止尾批卡住
    loop {
        tokio::select! {
            Some(outcome) = rx.recv() => {
                buf.push(outcome);
                if buf.len() >= 500 { flush_validation_batch(&db, &mut buf)?; }
            }
            _ = ticker.tick() => { if !buf.is_empty() { flush_validation_batch(&db, &mut buf)?; } }
            else => break,
        }
    }
    flush_validation_batch(&db, &mut buf)
});
```
`flush_validation_batch` 用一条 `UPDATE ... FROM UNNEST(...)` 写完整批，
`RETURNING id` 拿回受影响 id 用于更新内存池和重建快照。
DB 往返从 **每代理 3-5 次** 降到 **每 500 代理 1-2 次**。

这一条同时是 S2-3（连接池）的前置：它把并发 DB 调用方从 ~200 个降到 1 个。

### S2-2　`sync_proxy_bindings` 逐条往返

`src/api/subscription.rs:1100-1111`
```rust
for (id, port) in &assignments {
    state.pool.set_local_port(id, *port);
    state.db.update_proxy_local_port(id, *port as i32).ok();      // 往返 1
    state.db.clear_proxy_binding_failures(id).ok();                // 往返 2
}
for id in &selected_ids {
    if !assigned_ids.contains(id.as_str()) {
        state.db.update_proxy_local_port_null(id).ok();             // 往返 3
```
`prebound_proxies = 500` → 每轮绑定同步约 1000+ 次串行往返；
`max_rounds_per_run = 20` → **单次验活运行约 2 万次串行 round-trip**。
本机 0.3ms/次 ≈ 6s；DB 在网络另一侧（1-2ms RTT）就是 **20-40s 纯延迟**。

合成两条语句：
```sql
-- 已分配
UPDATE proxies p SET local_port = v.port, binding_failure_count = 0,
                     last_binding_failure = NULL, updated_at = now()
FROM UNNEST($1::text[], $2::int[]) AS v(id, port) WHERE p.id = v.id;

-- 未分配
UPDATE proxies SET local_port = NULL, updated_at = now() WHERE id = ANY($1::text[]);
```
这是投入产出比最高的单点改动之一：两行代码换掉 2 万次往返。

### S2-3　连接池

`src/db.rs:6-8` `conn: Mutex<Client>`，`src/db.rs:254-262` `with_conn` + `block_in_place`。
全库 **88 处** `with_conn`、应用侧 **72 处** `.db.` 调用共用一条连接。

做完 S1（热路径出表）+ S2-1（批量写回）+ S2-2（绑定批量化）之后，
并发 DB 调用方已经从"200 个验活任务 + 每个客户端连接"降到"少量后台任务 + 管理 API"。
此时一个小的**同步**池就够了，且 `with_conn` 签名不变——**88 个调用点零改动**：

```toml
r2d2 = "0.8"
r2d2_postgres = "0.18"
```
```rust
pub struct Database { pool: r2d2::Pool<PostgresConnectionManager<NoTls>> }

fn with_conn<T>(&self, f: impl FnOnce(&mut Client) -> Result<T, postgres::Error>)
    -> Result<T, postgres::Error>
{
    tokio::task::block_in_place(|| {
        let mut conn = self.pool.get().map_err(/* ... */)?;
        f(&mut conn)
    })
}
```
池大小 8-16（与 GPT 建议一致）。注意 `Database::new` 的 `migrate()` 要显式取一条连接执行，
避免迁移期间其他连接看到半迁移状态。

是否进一步全面异步化，见 §6。

### S2-4　质检限流器持锁 sleep

`src/quality/checker.rs:44-51`
```rust
async fn wait(&self) {
    let mut last = self.last_call.lock().await;
    let elapsed = last.elapsed();
    if elapsed < self.min_interval {
        tokio::time::sleep(self.min_interval - elapsed).await;   // ← 持锁睡眠
    }
    *last = Instant::now();
}
```
`RateLimiter::new(40)` → `min_interval = 1.5s`。持锁 sleep 使 N 个任务严格排成
0 / 1.5 / 3.0 / 4.5s …，`max_checks_per_run = 200` → **仅排队 300s**。
更糟：`wait()` 是在**已持有 semaphore permit** 之后调用的
（`checker.rs:321` 取 permit，`checker.rs:550` 才 wait），
所以 `concurrency = 10` 的槽位大部分时间在空转等限流。

锁内只做预约，锁外睡：
```rust
async fn wait(&self) {
    let sleep_until = {
        let mut next = self.next_slot.lock().await;
        let at = (*next).max(Instant::now());
        *next = at + self.min_interval;         // 预约下一个槽位
        at
    };                                           // 锁已释放
    tokio::time::sleep_until(sleep_until).await; // 各任务并行等自己的槽位
}
```
配合 S4-3（按出口 IP 去重）会进一步减少需要走 ip-api 的次数。

### S2-5　复用 HTTP Client；谨慎合并请求

`validator.rs:599-606`（`validate_single`）和 `validator.rs:540-547`（`detect_exit_ip`）
各自 `Client::builder()...build()`。一次验活流程最多建 3 个 Client
（主探测 + 兜底探测 + 出口 IP），每次都重建 rustls `ClientConfig` 并加载根证书库。
`pool_max_idle_per_host(0)` 又保证连接零复用。

**先做**：一次验活流程内共享一个 Client；或在 `AppState` 放
`DashMap<u16, reqwest::Client>` 按 `local_port` 缓存（端口在一轮绑定内稳定），
绑定回收时清理。同时给整个代理级别一个总 deadline，
而不是每个请求各自享有完整 `timeout_secs`（GPT 这条建议是对的）。

**推迟**：把 `cdn-cgi/trace` 合并为唯一探测（第一版 P0-11）。
**必须在 S0-1 之后做**，且合并后的语义要是：
```
trace 成功           → 存活 + 出口 IP 已知
trace 失败 → 204 探活 → 存活 + 出口 IP 未知     ← 不是 invalid
204 也失败           → 不存活
```
只有保持这个三态，合并才是纯收益；否则等于把误杀概率绑到单个第三方端点上。

### S2-6　订阅列表每次请求全表扫描

`src/api/subscription.rs:89-93`（路由 `GET /api/subscriptions`，`api/mod.rs:94-95`，**无缓存**）
```rust
pub async fn list_subscriptions(...) {
    let subs = state.db.get_subscriptions()?;
    let (duplicate_stats, overlap_edges) = state.db.get_subscription_duplicate_overview()?;
```
`db.rs:929-959` 在 `with_conn` 内部：
```rust
let exact_rows = conn.query("SELECT ... FROM proxies WHERE orphaned_at IS NULL", &[])?;
for row in &exact_rows {
    let proxy = proxy_from_row(row);                        // 每行一次 serde_json 解析
    exact_sources.entry(proxy_row_definition_key(&proxy))
        .or_default().insert(proxy.subscription_id);
}
for sources in exact_sources.values() {
    for left in 0..sources.len() {
        for right in (left+1)..sources.len() { ... }         // O(k²)
    }
}
```
**全量 `proxies`（含 `config_json`）过网络 + 2 万次 JSON 解析 + O(k²) 配对，
全程持有全局 DB 锁。** 管理员每次打开订阅列表，整个应用（含数据平面）停顿。

`get_stats` 已经有缓存（`fetch.rs:213-232` `dashboard_stats_cache`），这里却没有。

两步修：
1. **立刻**：加缓存 + 拆接口。基础列表和重复分析拆成两个端点，
   重复分析加 TTL 缓存（复用 `dashboard_stats_cache` 的模式），并在订阅增删时失效。
2. **随 S3-3**：有了 `definition_hash` 后整体下推 SQL，Rust 侧的 HashMap 合并
   （`db.rs:1018-1049`）全部删掉：
```sql
WITH def_sources AS (
    SELECT DISTINCT definition_hash, subscription_id
    FROM proxies WHERE orphaned_at IS NULL
)
SELECT a.subscription_id AS left_id, b.subscription_id AS right_id, COUNT(*) AS shared_exact_nodes
FROM def_sources a JOIN def_sources b USING (definition_hash)
WHERE a.subscription_id < b.subscription_id
GROUP BY 1, 2
```

### S2-7　最终审核补充：定向绑定与订阅刷新仍有 N+1

首轮落地只合并了端口写回，定向绑定仍对每个目标调用一次 `get_proxy_record`；订阅刷新也仍对
每个保留节点各开一个配置更新事务，并逐条标记/删除移除项。最终实现改为：目标 ID 保序
`UNNEST` 批量读取；刷新配置批量 upsert；孤儿标记和无效项删除各一条批量语句。绑定失败也
按定义批量累计并退避，本地端口分配失败不再自动删除订阅库存。

连接池超时兜底同时限制为最多一条额外直连，避免高峰期绕过 `max_connections` 形成连接风暴。

---

## S3　Schema 与索引

需要迁移脚本，`src/bin/migrate_sqlite_to_postgres.rs` 同步更新。

### S3-1　时间列 `TEXT` → `TIMESTAMPTZ`

`created_at / updated_at / last_validated / checked_at / orphaned_at / last_refresh_at /
last_binding_failure / expires_at` 全是 `TEXT`（`db.rs:268-390`）。

- 索引膨胀：RFC3339 25-32 字节 vs `timestamptz` 8 字节。
  `idx_proxies_hot_selection` 这类 4 列复合索引直接大 3-4 倍。
- 字符串 collation 比较慢于整数比较一个量级。
- 语义脆弱：`db.rs:3162` 的 `COALESCE(better_p.last_validated, '') > COALESCE(p.last_validated, '')`
  ——任何一处写入用 `+08:00` 而非 `Z`，排序即错。
- Rust 侧反复解析：`parse_rfc3339_utc`（`db.rs:3331`）、
  `quality_checked_at_is_stale`（`checker.rs:451`）逐行解析字符串。

```toml
postgres = { version = "0.19", features = ["with-chrono-0_4", "with-serde_json-1"] }
```
Rust 侧 `String` → `chrono::DateTime<Utc>`，序列化到 JSON 仍是 RFC3339，**前端无感**。
这一条是 S4 状态机（`next_check_at` 上的调度查询）的前置。

### S3-2　`extra_json` → `JSONB` + 物化过滤列

`db.rs:1245-1248`
```sql
OR COALESCE((q.extra_json::jsonb ->> 'schema_version')::int, 0) < $3
OR ( ... AND COALESCE((q.extra_json::jsonb ->> 'incomplete_retry_count')::int, 0) < $2 )
```
`TEXT → jsonb` 强制转换**每行重新解析 JSON**且无法走索引 → 每次质检选取都是
全表扫描 + 全量 JSON 解析。

```sql
ALTER TABLE proxy_quality ALTER COLUMN extra_json TYPE jsonb USING extra_json::jsonb;
ALTER TABLE proxy_quality ADD COLUMN IF NOT EXISTS schema_version INT NOT NULL DEFAULT 0;
ALTER TABLE proxy_quality ADD COLUMN IF NOT EXISTS incomplete_retry_count INT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_proxy_quality_due ON proxy_quality(schema_version, checked_at);
```
写入侧在 `checker.rs:366-378` 构造 `ProxyQuality` 处顺带填这两列。

### S3-3　`definition_hash`

重复判定当前是：拉全行 → `serde_json` 解析 `config_json` → 算 key → Rust 比较
（`subscription.rs:738-750`、`db.rs:1804-1838`）。
`get_exact_duplicate_proxy_ids` 被 `update_exact_duplicate_validation`（每个验活结果一次）和
`inherit_exact_duplicate_states`（每个新节点一次）反复调用。

```sql
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS definition_hash BYTEA;
CREATE INDEX IF NOT EXISTS idx_proxies_definition_hash
    ON proxies(definition_hash) WHERE orphaned_at IS NULL;
```
Rust 侧在 parser / insert 处算 `sha256(definition_key)` 一次并写入。之后：
```sql
UPDATE proxies SET is_valid = $2, error_count = ..., last_validated = $3, updated_at = $3
WHERE definition_hash = (SELECT definition_hash FROM proxies WHERE id = $1)
RETURNING id
```
一条语句替代原来的 2 SELECT + N UPDATE。
`inherit_exact_duplicate_states`（`db.rs:1847-1910`，当前每个 target 2+K 次查询）
同样塌缩为单条 `UPDATE ... FROM (SELECT DISTINCT ON (definition_hash) ...)`。

### S3-4　`insert_proxies_batch` 逐行插入

`db.rs:841-862` 在事务内逐行 `tx.execute`——事务省了 fsync，但没省 round-trip。
改 `UNNEST` 多行插入或 `COPY`：
```rust
conn.execute(
    "INSERT INTO proxies (id, subscription_id, name, proxy_type, server, port,
                          config_json, definition_hash, is_valid, error_count,
                          created_at, updated_at)
     SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[],
                          $6::int[], $7::text[], $8::bytea[], $9::bool[], $10::int[],
                          $11::timestamptz[], $12::timestamptz[])
     ON CONFLICT (id) DO UPDATE SET ...",
    &[&ids, &sub_ids, &names, /* ... */],
)?;
```

### S3-5　`unique_exit_ip` 相关子查询 → 窗口函数

`db.rs:3142-3182`：`NOT EXISTS (SELECT 1 FROM proxy_quality better_q JOIN proxies better_p ...)`
外层每行跑一次带 JOIN 的子查询，内部还有 8 个 OR 分支的比较链——本质 O(n²)。

```sql
WITH ranked AS (
    SELECT p.id, ROW_NUMBER() OVER (
               PARTITION BY q.ip_address
               ORDER BY p.is_valid DESC, p.error_count ASC,
                        p.last_validated DESC NULLS LAST, p.updated_at DESC, p.id ASC
           ) AS rn
    FROM proxies p JOIN proxy_quality q ON q.proxy_id = p.id
    WHERE p.orphaned_at IS NULL
      AND q.ip_address IS NOT NULL AND BTRIM(q.ip_address) <> ''
)
-- 条件：q.ip_address IS NULL OR BTRIM(q.ip_address) = '' OR p.id IN (SELECT id FROM ranked WHERE rn = 1)
```
排序语义与原比较链等价。改 `timestamptz` 后原 `COALESCE(..., '')` 换成 `NULLS LAST`。

### S3-6　索引

```sql
CREATE EXTENSION IF NOT EXISTS pg_trgm;
-- 搜索：db.rs:3190-3194 的 %keyword% ILIKE 目前是全表扫 + 逐行三次 ILIKE
CREATE INDEX IF NOT EXISTS idx_proxies_name_trgm   ON proxies USING gin (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_proxies_server_trgm ON proxies USING gin (server gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_quality_ip_trgm ON proxy_quality USING gin (ip_address gin_trgm_ops);

-- 国家筛选（filter_proxies 用 eq_ignore_ascii_case，SQL 侧应对齐）
CREATE INDEX IF NOT EXISTS idx_quality_country_upper ON proxy_quality(UPPER(country), proxy_id);

-- S4 状态机调度
CREATE INDEX IF NOT EXISTS idx_proxies_next_check ON proxies(next_check_at, health_state, id);

-- 订阅 URL 标准化后唯一索引（现在靠 insert_subscription_with_proxies_unless_url_exists 兜）
```
同时按 GPT 建议清理低选择性单列布尔索引：`idx_proxies_is_valid`、
`idx_proxy_quality_chatgpt`、`idx_proxy_quality_google`、`idx_proxy_quality_residential`
选择性都很差（2 个值），换成面向实际查询的部分复合索引。

补外键和 `ON DELETE CASCADE`：`proxies.subscription_id → subscriptions.id`、
`proxy_quality.proxy_id → proxies.id` 目前都没有 FK
（`db.rs:289-327`），靠 `cleanup_high_error_proxies` 手动两步删除维持一致性。

### S3-7　`list_proxy_page` 两次取锁

`db.rs:1599-1620` 与 `db.rs:1671` 是两次独立 `with_conn`：两次锁竞争，
且两次查询间表可能变化（`filtered` 与实际返回不一致）。合并到一个 `with_conn`。

游标分页本身已做得不错（`cursor.is_none()` 才跑 COUNT、多取一行判 `has_next`）——保留。
按 GPT 建议，可进一步把总数改为独立缓存或按需查询。

---

## S4　调度模型重构（采纳 GPT 的健康状态机）

当前验活调度是"按 cohort 批量扫表"（`get_validation_proxy_records`，`db.rs:1318`），
用 `new_limit / valid_limit / invalid_limit` 三个配额防饿死。
这个设计的问题：每轮都要重新扫描并排序全表，且无法表达"这个代理下次什么时候该检"。

改为**每个代理自带下次检查时间**：

```sql
ALTER TABLE proxies
  ADD COLUMN health_state TEXT NOT NULL DEFAULT 'untested',   -- untested|healthy|suspect|unhealthy
  ADD COLUMN consecutive_failures INT NOT NULL DEFAULT 0,
  ADD COLUMN last_success_at TIMESTAMPTZ,
  ADD COLUMN last_failure_at TIMESTAMPTZ,
  ADD COLUMN next_check_at   TIMESTAMPTZ,
  ADD COLUMN failure_kind    TEXT;      -- timeout|refused|tls|http|exit_ip_unavailable|...
```

状态迁移：`untested → healthy → suspect → unhealthy`
- 新代理 `next_check_at = now()`，立即检测。
- healthy：按 TTL + 随机抖动复检（抖动很重要——否则同一批导入的代理会永远同批到期，
  形成周期性尖峰）。
- 失败：`suspect`，退避 5 / 15 / 60 / 180 分钟。
- 连续失败达阈值才转 `unhealthy` 下线，**保留记录**（呼应 S0-1，不再 `DELETE`）。

`failure_kind` 让 S0-1 的区分落地：`exit_ip_unavailable` 不计入 `consecutive_failures`。

调度查询变成一条索引扫描，且天然支持多实例：
```sql
SELECT id FROM proxies
WHERE next_check_at <= now() AND health_state <> 'unhealthy'
ORDER BY next_check_at
LIMIT $1
FOR UPDATE SKIP LOCKED
```
`FOR UPDATE SKIP LOCKED` 让多个 worker（甚至多进程）安全并行取任务，
不再需要 `validation_running` 这个进程内 `AtomicBool`（`main.rs:52`）。

### S4-1　质检拆成基础 / 完整两档

现在一次质检固定跑全部 10 个服务（`unlock.rs:88-100`），
其中 `chatgpt`/`copilot`/`netflix`/`tiktok` 各有 2 个子请求，`chatgpt`/`sora` 成功路径
还会追加 `trace_region` → **每代理 13-15 次 HTTP 请求**，
加上 `redirect::Policy::limited(5)` 的重定向，实际网络请求更多。
统一 30s 超时（`checker.rs:523`），而 `quality.concurrency = 10`。

拆分：
- **基础质检**（高频）：出口 IP、国家、ASN、风险分、Google、ChatGPT
  ——正好对应 `proxy_quality` 表里真正有列的字段，也是 `proxy_listener` 筛选用的字段。
- **完整质检**（手动触发或长周期）：Netflix、Claude、Sora、TikTok、Spotify、
  YouTube Premium、Gemini、Copilot。

再加一个优化并明确一条边界：
- **不做跨服务短路**：Google 不可用不能证明 ChatGPT、Netflix 等服务也不可用；基础档并行
  检查 Google/ChatGPT，完整档并行检查其余服务。以 Google 结果短路会降低查询质量，已拒绝。
- **独立超时**：解锁检测 8-10s 足够判断可达性，与 IP 情报查询的 30s 分开。

### S4-2　IPPure 与解锁检测并行

`checker.rs:532-563`
```rust
let ippure_result = query_ippure(&client).await;    // 串行第 1 段
let need_ip_api = ...;                               // 依赖上面的结果
let (ipapi, ipinfo, unlock) = tokio::join!(...);      // 串行第 2 段
```
`unlock::check_all` **完全不依赖** IPPure 结果，却被推到第二段。
它是整个质检里最慢的部分，把它的启动提前一整个 RTT 是净收益：
```rust
let unlock_fut = crate::quality::unlock::check_all(&client);   // 先起跑，不 await
let ippure_result = query_ippure(&client).await;
let (ipapi_result, ipinfo_result, unlock_report) = tokio::join!(
    async { if need_ip_api { rate_limited_ip_api(&client, rl).await } else { None } },
    async { if need_ipinfo { query_ipinfo(&client).await } else { None } },
    unlock_fut,
);
```

### S4-3　质检按出口 IP 收敛

质检的本质是**测出口 IP 的属性**。同一出口 IP 上的多个节点，地理/风险/解锁结果必然相同。

现在 `run_subscription_quality_check`（`checker.rs:242-250`）只按
`proxy_row_definition_key` 去重，`get_due_quality_proxy_records`（`db.rs:1230`）
没有任何出口 IP 收敛。

```sql
SELECT DISTINCT ON (COALESCE(q.ip_address, p.id)) ...
FROM proxies p LEFT JOIN proxy_quality q ON q.proxy_id = p.id
WHERE ...
ORDER BY COALESCE(q.ip_address, p.id), q.checked_at ASC NULLS FIRST, p.updated_at DESC
```
每组只测一个代表，结果写回同 `ip_address` 的所有行。
按 1.5-3 个节点共享一个出口 IP 保守估计，**质检工作量减少 33%-66%**。

按 GPT 建议再加一条：对比 IPPure / IPInfo / ip-api / 验活出口 IP，
**IP 不一致时不要混合字段**——现在 `checker.rs:576-603` 是逐字段 `.or()` 回退，
如果三个来源看到的是不同 IP（代理出口轮换），合成出的记录是几个 IP 的混合体。
应先确认 IP 一致，不一致则以其中一个为准并标记 `ip_mismatch`。

---

## S5　数据模型规范化（战略方向）

当前一个物理节点出现在 3 个订阅里 = **3 行 `proxies` + 3 行 `proxy_quality`**，
健康状态和质量数据重复存储。整套"exact duplicate"机制
（`get_exact_duplicate_proxy_ids`、`inherit_exact_duplicate_states`、
`update_exact_duplicate_validation`、`upsert_exact_duplicate_quality`）
存在的唯一目的就是把这份重复**事后同步回一致**。

规范化方向是对的，最终落地为五张核心事实表：

```
proxy_definitions   (definition_hash PK, proxy_type, server, port, config_json)
subscription_proxies(subscription_id, definition_hash)        -- 多对多映射
proxy_health        (definition_hash PK, health_state, consecutive_failures, next_check_at, ...)
exit_quality        (ip_address PK, country, asn, risk, unlock_json, checked_at)
proxy_exit          (definition_hash → ip_address)             -- 最近一次观测到的出口
```

另有三张职责独立的运行/调度表：`proxy_runtime`、`quality_retry_state`、
`quality_check_leases`。`normalized_proxies` 与 `normalized_proxy_quality` 是兼容读取视图，
不是新的事实副本。这样避免把端口绑定、无出口 IP 的重试状态和租约重新塞回核心表。

收益不只是省空间：
- **S3-3 的 `definition_hash` 就是这里的主键**，所以 S3-3 是这一步的自然铺垫。
- 健康状态天然唯一 → 整个 duplicate-sync 子系统可以**整体删除**。
- 质量数据挂在 `ip_address` 上 → S4-3 的"按出口 IP 收敛"从优化变成模型内建性质。
- 订阅重叠分析（S2-6）变成 `subscription_proxies` 上的一次自连接。

这是最后做的一步，但前面的 S3-3 / S4-3 都应该朝这个方向铺路，避免走回头路。

---

## 6. 关于连接池顺序的分歧

GPT 报告把「`sqlx::PgPool` / `deadpool-postgres` 全面异步化」列为 P0 第一项。
第一版方案我也把连接池放在 P0 第一位。**现在我认为都应该往后放。** 理由：

连接池解决的是**并发争用**。但并发争用的来源是可以先消掉的：

| 争用来源 | 消除方式 | 消除后的并发 DB 调用方 |
|---|---|---|
| 每个客户端连接一次全表查询 | S1 内存快照 | 0（完全出表） |
| 200 个验活任务各自写库 | S2-1 批量写回 | 1（单写入任务） |
| 每个绑定 2 次往返 × 1000 | S2-2 UNNEST 合并 | 2 条语句 |
| 订阅列表全表扫描 | S2-6 缓存 + 下推 | 缓存命中时 0 |

做完这四条，峰值并发 DB 调用方从"200 验活任务 + 每客户端连接"降到
"少量后台任务 + 管理 API 请求"。此时 `r2d2` + 8-16 连接已经绰绰有余，
而且 `with_conn` 签名不变 → **88 个调用点零改动**。

反过来先做全异步化：要改 88 个方法签名 + 72 个调用点全部加 `.await`，
风险面覆盖整个应用，而收益的大部分（消除串行）其实被上面四条拿走了。

**但这不是"永远不做"。** 设一个可测量的触发条件，做完 S2 再判断：

- `with_conn` 等待时间 p99 > 50ms，或
- tokio worker 线程数在验活期间显著超过 CPU 核数（`block_in_place` 膨胀的信号），或
- 出现单条语句无法批量化、但又必须高并发的新需求

任一条成立，就执行 `deadpool-postgres` 全异步迁移。否则 `r2d2` 保持。

需要承认 GPT 这条建议的合理之处：`block_in_place` 即使配了池仍然占用 worker 线程，
而且迁移做两次（先 r2d2 再 deadpool）总成本高于直接做一次。
如果团队本来就打算长期演进这个项目、且能承受一次大范围改动，
直接上 `deadpool-postgres` 是可以接受的选择——**只是不该排在 S0/S1 之前。**

---

## 7. 落地顺序

```
S0  止血（无 schema 变更，可独立上线/回滚）
    S0-1  验活误杀 + 停止 DELETE            ← 最先做，它在持续制造工作量
    S0-2  解锁 error ≠ unavailable

S1  数据平面（无 schema 变更）
    S1-1  内存选择快照，去掉热路径 ORDER BY RANDOM()

S2  控制平面吞吐（无 schema 变更）
    S2-1  验活/质检批量写回
    S2-2  sync_proxy_bindings UNNEST 合并
    S2-4  RateLimiter 不持锁 sleep
    S2-5  复用 reqwest::Client + 总 deadline
    S2-6  订阅列表加缓存 + 拆接口
    S2-7  定向绑定/订阅刷新批量读取与写回
    S2-3  r2d2 连接池          ← 放在本阶段最后，此时才能看清真实需求

S3  Schema（需迁移脚本，同步改 migrate_sqlite_to_postgres.rs）
    S3-1  timestamptz
    S3-2  jsonb + 物化 schema_version / incomplete_retry_count
    S3-3  definition_hash + 回填
    S3-4  UNNEST 批量插入
    S3-5  unique_exit_ip 窗口函数
    S3-6  pg_trgm / 复合索引 / 外键 CASCADE
    S3-7  list_proxy_page 合并取锁
    S2-6 第二步：重复分析下推 SQL

S4  调度模型（依赖 S3-1）
    S4    健康状态机 + next_check_at + 指数退避 + SKIP LOCKED
    S4-1  基础/完整质检拆分 + 服务并行检测 + 独立超时
    S4-2  IPPure 与 unlock 并行
    S4-3  质检按出口 IP 收敛 + IP 不一致检测
    S2-5 第二步：合并 trace 为主探测（三态语义）

S5  数据模型规范化（核心五表 + 独立运行/调度表，删除 duplicate-sync 子系统）
```

S0 和 S1 是 5 个阶段里唯一"必须先做"的部分；S2 内部各条互相独立，可并行推进。

---

## 8. 先量基线

改之前必须先有基线，否则无法判断改动是否有效：

```sql
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
SELECT calls, total_exec_time, mean_exec_time, rows, query
FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 20;

ALTER SYSTEM SET log_min_duration_statement = '200ms';
SELECT pg_reload_conf();
```

预期能验证本方案的几个特征信号：

- **N+1 的指纹**：`calls` 极大、`mean_exec_time` 很小、`total_exec_time` 排名靠前。
  `update_proxy_local_port` 和 `clear_proxy_binding_failures`（S2-2）应该非常显眼。
- **热路径**：`get_random_valid_proxy_records` 的 `calls` 应该约等于客户端连接数，
  `mean_exec_time` 随节点数增长——这能直接证实/否证 S1 的优先级。
- **全表扫描**：`get_subscription_duplicate_overview` 的 `rows` 应该约等于全表行数。

对这几条跑 `EXPLAIN (ANALYZE, BUFFERS)`：
`get_random_valid_proxy_records`（S1）、
`list_proxy_page` 带 `unique_exit_ip=true`（S3-5）、
`get_due_quality_proxy_records`（S3-2）、
`get_subscription_duplicate_overview`（S2-6）。

应用侧建议补的指标：
- `with_conn` 等待时间直方图 —— §6 的决策依据，必须有
- 一次完整验活运行的墙钟时间、每轮 DB 往返次数
- 质检中"等限流"累计时长 vs "实际网络请求"累计时长（验证 S2-4）
- **因 `exit_ip_unavailable` 被判失败的代理数** —— 验证 S0-1 修复效果的直接指标
- 解锁检测中 `status == "error"` 的比例 —— 验证 S0-2

---

## 9. 最终落地审核

| 阶段 | 最终状态 | 主要验收证据 |
|---|---|---|
| S0 | 完成 | 出口 IP 失败不改变存活；解锁三态、退避和旧布尔保留均有单测；自动验活不删高错误库存 |
| S1 | 完成 | 数据平面只读 ArcSwap 快照；按出口去重、过滤、风险阈值、失败冷却和替代定义均有单测 |
| S2 | 完成 | 验活/质检/绑定/订阅刷新批量化；重复分析拆接口并单航班缓存；连接池和运行指标已接入 |
| S3 | 完成 | typed timestamp/JSONB、哈希、UNNEST、窗口查询、索引和外键均由 PostgreSQL 集成测试执行 |
| S4 | 完成 | 健康租约用 `SKIP LOCKED`；质量租约按出口领取；基础/完整档、并行探测和 IP 一致性均已覆盖 |
| S5 | 完成（保留兼容归档） | 规范化表为运行时唯一事实源，duplicate-sync 已删除；旧 PostgreSQL 原地升级和 SQLite 导入均有测试 |

明确未做两项：不采用“Google 不可用就跳过其他服务”的低质量短路；不在应用启动时物理
`DROP` 旧 `proxies/proxy_quality` 表。后者属于不可逆部署清理，应在备份、回滚窗口和生产
观察期之后单独执行。所有加速比仍需用生产规模数据实测。

---

## 附：收益量级（估计，需实测确认）

| 改动 | 影响面 | 预期 |
|---|---|---|
| S0-1 停止误杀与删除 | 验活 | 消除"删除→刷新→重验"空转循环；止住可用池流失 |
| S0-2 解锁三态 | 质检/可用池 | 消除瞬时抖动导致的 72 小时假阴性 |
| S1 内存快照 | **数据平面** | 每连接从 O(N log N) 全表两次排序降到 O(count) |
| S2-1 批量写回 | 验活 | DB 往返从每代理 3-5 次降到每 500 代理 1-2 次 |
| S2-2 绑定批量化 | 验活 | 每次运行减少约 2 万次串行往返 |
| S2-4 限流不持锁 | 质检 | 200 候选排队从约 300s 降到并行等待 |
| S2-6 订阅列表 | 管理 API | 消除"打开列表 → 全应用停顿" |
| S3-1/S3-2 类型修正 | 查询 | 索引体积降 3-4 倍；消除逐行 JSON 解析 |
| S3-5 窗口函数 | 列表查询 | `unique_exit_ip` 从 O(n²) 降到一次扫描 |
| S4-1 质检拆档 | 质检 | 高频路径请求数从 13-15 降到 2-4 |
| S4-3 出口 IP 收敛 | 质检 | 工作量减少 33%-66% |
| S5 规范化 | 全局 | 删除整个 duplicate-sync 子系统 |
