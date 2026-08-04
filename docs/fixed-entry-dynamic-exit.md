# 固定入口、动态/固定出口模式维护文档

> 最后更新：2026-08-04
>
> 适用项目：ZenProxy
>
> 运行态数据会变化；节点数量、用户数量和当前出口请以管理后台或数据库实时结果为准。
>
> 目标边界：这是自用型代理池，只追求接近商业代理网关的使用体验，不建设计费、套餐或流量额度系统。

## 1. 模式定位

固定入口、动态出口模式把 ZenProxy 暴露为一个标准代理网关：

```text
业务程序
  → 固定入口（服务器 IP:50089）
  → ZenProxy SOCKS5/HTTP Listener
  → 从代理池选择出口
  → sing-box 动态绑定
  → 上游代理节点
  → 目标网站
```

业务程序只需要保存一个固定的代理地址。随机和定时模式会按 URL 策略选择出口；固定槽位模式会持续使用已分配出口，并在失效后自动补充同国家的新出口。

这种模式最适合：

- 原项目已经支持 HTTP 或 SOCKS5 代理。
- 希望只替换代理地址，不改造成 Relay API。
- 多台业务机器共享一个自建代理池。
- 希望由服务端统一验活、筛选和故障切换。

## 2. 当前部署入口

| 项目 | 当前值 | 说明 |
|---|---:|---|
| 公网代理端口 | `50089/tcp` | 远程业务程序连接的端口 |
| 容器代理端口 | `1080/tcp` | ZenProxy 容器内 Listener |
| Web API 宿主机端口 | `127.0.0.1:30595` | 仅供宿主机 Nginx 使用 |
| 输入协议 | HTTP、HTTP CONNECT、SOCKS5 | 同一端口自动检测 |
| SOCKS5 UDP | 不支持 | 当前只实现 CONNECT |
| 当前 Listener 数量 | 1 | 一组静态用户名和密码 |

端口映射定义在 `compose.yml`：

```yaml
ports:
  - "127.0.0.1:${ZENPROXY_HOST_PORT}:3000"
  - "${ZENPROXY_PROXY_BIND_IP}:${ZENPROXY_PROXY_PORT}:1080"
```

实际密码只保存在 `.env`，不得写入本文、README、Git 或日志。

## 3. 连接处理流程

每个客户端 TCP 连接按以下流程处理：

1. Listener 接受连接并读取首字节。
2. `0x05` 按 SOCKS5 处理，其他内容按 HTTP 代理处理。
3. 验证用户名和密码。
4. 从用户名后缀解析国家、住宅、协议等筛选条件。
5. 从 PostgreSQL 选择最多 3 个候选节点。
6. 候选必须已验活、仍属于有效订阅且已检测到出口 IP。
7. 同一批候选按真实出口 IP 去重。
8. 为候选节点复用或按需创建 sing-box 本地绑定。
9. 通过该本地绑定连接目标地址。
10. 成功后在客户端和上游之间双向复制 TCP 数据。
11. 连接结束后释放使用计数；空闲绑定后续由后台清理。

每个连接最多尝试 3 个候选节点。三个候选都失败时：

- HTTP 返回 `502 Bad Gateway`。
- SOCKS5 返回连接失败。
- 当前 Listener 失败不会立即把节点标记为无效；节点状态主要由后台验活更新。

## 4. 支持的入口协议

### 4.1 HTTP 代理

支持普通 HTTP 代理请求：

```bash
curl -x "http://USER:PASSWORD@SERVER_IP:50089" \
  http://example.com/
```

### 4.2 HTTP CONNECT

HTTPS 请求通过 CONNECT 隧道转发：

```bash
curl -x "http://USER:PASSWORD@SERVER_IP:50089" \
  https://httpbin.org/ip
```

### 4.3 SOCKS5

支持 SOCKS5 用户名密码认证和 TCP CONNECT：

```bash
curl -x "socks5h://USER:PASSWORD@SERVER_IP:50089" \
  https://httpbin.org/ip
```

建议使用 `socks5h`，让域名解析发生在代理链路中。

当前不支持：

- SOCKS5 UDP ASSOCIATE。
- 在一个已建立的隧道中切换出口。
- WebSocket 专用处理；WebSocket 能否工作取决于其是否完整运行在现有 TCP 隧道内。

## 5. 认证和筛选语法

当前每个 Listener 配置一组基础用户名和密码：

```text
USER:PASSWORD@SERVER_IP:50089
```

可以在基础用户名后增加筛选后缀，密码保持不变。

| 后缀 | 作用 | 示例 |
|---|---|---|
| `-country-XX` | 指定出口国家 | `USER-country-US` |
| `-residential` | 只选择住宅 IP | `USER-residential` |
| `-chatgpt` | 只选择 ChatGPT 可用出口 | `USER-chatgpt` |
| `-google` | 只选择 Google 可用出口 | `USER-google` |
| `-type-TYPE` | 指定上游代理协议 | `USER-type-vless` |
| `-session-ID-rotate-SECONDS` | 按 Session 在指定秒数内固定出口，到期轮换 | `USER-session-crawler_01-rotate-300` |
| `-fixed-SLOT` | 使用当前数据库账号拥有的固定出口槽位 | `zp_xxx-fixed-f123abc` |

后缀可以组合：

```text
USER-country-US-residential
USER-country-JP-chatgpt
USER-country-US-residential-google-type-vless
USER-country-US-session-crawler_01-rotate-300
```

`session` 和 `rotate` 必须成对出现。Session ID 限制为 1～32 个字母、数字或下划线，轮换间隔为 1～86400 秒。

网关模式目前不能通过普通筛选后缀指定：

- 风险评分。
- 城市、州、省。
- ASN。
- ISP 或运营商。
- 延迟。
- 任意未分配的 `proxy_id`。
- 任意未分配的具体出口 IP。

这些能力中的一部分已存在于 Relay API，但尚未接入 Listener 用户名语法。

## 6. 出口选择规则

随机选择使用以下基础条件：

- `is_valid = true`。
- `orphaned_at IS NULL`。
- 必须存在非空的质检出口 IP。
- 按真实出口 IP 去重。
- 优先错误次数少的节点。
- 同等优先级内随机排序。
- 最近发生错误的节点优先级较低。

普通随机模式中，同一连接获得的最多 3 个候选出口不会重复，但不同连接之间没有历史排除状态。

因此当前语义是：

```text
新连接 1 → 随机出口 A
新连接 2 → 随机出口 B，也可能再次为 A
新连接 3 → 随机出口 C，也可能再次为 A 或 B
```

普通随机模式不保证：

- 与上一次连接使用不同 IP。
- 按顺序轮询所有 IP。
- 同一用户独占某个 IP。
- 不同用户不会同时使用同一出口。

## 7. 轮换粒度与长连接

出口是在新 TCP 连接建立时选择的，不是在每个 HTTP 请求时选择。当前有三种可同时使用的 URL 级别模式：

- 不带 `session/rotate` 后缀：每个新 TCP 连接随机出口。
- 带 `-session-ID-rotate-SECONDS`：同一账号、Session、间隔和筛选条件在到期前使用同一出口。
- 带 `-fixed-SLOT`：持续使用持久化槽位当前分配的出口。

客户端不复用连接时：

```text
请求 1 → TCP 连接 1 → 出口 A
请求 2 → TCP 连接 2 → 出口 B
请求 3 → TCP 连接 3 → 出口 C
```

客户端使用 Keep-Alive 或连接池时：

```text
请求 1 ─┐
请求 2 ─┼→ TCP 连接 1 → 同一个出口 A
请求 3 ─┘
```

HTTP CONNECT 和 SOCKS5 隧道不能在连接中途无感更换 IP。强制切换只能关闭旧连接并建立新连接。

定时模式的周期从该 Session 首次成功建立上游连接时开始，不会因为周期内继续使用而延长。到期后的第一条新连接触发换点：

- 优先排除上一个已测出口 IP。
- 并发到期连接通过每 Session 锁收敛到同一个新出口。
- 新出口不可用时会继续尝试其他出口。
- 没有其他可用出口时，允许以上一个出口作为最后可用性回退。
- 服务重启会清空内存中的定时 Session，下一条连接会重新选择出口。

### 7.1 固定出口槽位

固定出口使用数据库账号拥有的持久化槽位，旧静态共享账号不能访问。槽位保存稳定的 `slot_key`、目标国家和可选质量条件，对外用户名形如：

```text
zp_xxx-fixed-f123abc
```

固定槽位遵循以下规则：

- 健康期间持续使用当前已测出口 IP。
- 出口无效、被订阅刷新标记为孤立或删除、出口 IP/国家变化时进入替换流程。
- 替换只选择槽位原国家，并继续满足申请时选择的类型、住宅、ChatGPT、Google 条件。
- 同一账号的不同槽位按出口 IP 去重。
- 请求时连接失败会立即尝试最多 3 个同国家候选；并发请求通过每槽位锁收敛到一个结果。
- 后台每 60 秒、验活后和质量检查后也会修复异常槽位。
- 同国家没有候选时保持不可用并返回失败，不跨区回退。
- 服务重启不会清空槽位，已建立的长连接仍然使用建立时的旧出口直到关闭。

用户页面支持按条件批量申请（默认 10 个）、从质量列表手动固定、手动同区更换、订阅勾选和删除。订阅勾选只控制导出内容，不会停用已经复制的槽位 URL。

固定订阅提供 Clash HTTP、Clash SOCKS5、HTTP URL 列表和 SOCKS5 URL 列表。链接使用账号独立、可轮换的 HMAC Token；内容只包含统一入口和槽位凭据，不泄露上游节点配置。

旧项目需要“尽量每请求换 IP”时，应：

- 关闭 HTTP Keep-Alive。
- 禁用或缩短客户端连接池复用。
- 每次请求完成后主动关闭代理连接。
- 接受随机选择仍可能连续重复 IP。

普通随机模式仍不保证与上一次不同；定时模式会记录上一个出口并优先排除，但在没有其他可用 IP 时仍会回退。

## 8. 并发与多用户现状

### 8.1 已支持

Listener 基于 Tokio 异步处理，可以：

- 接受多台机器同时连接。
- 接受同一账号的多个并发连接。
- 按 URL 策略为每条新连接随机选点，或复用定时 Session 出口。
- 并发使用持久化固定槽位，并在故障时收敛到同国家的新出口。
- 共享已经创建的 sing-box 动态绑定。
- 在连接传输期间保护绑定不被空闲清理。

固定端口本身不会限制并发用户数。实际容量取决于：

- 可用出口数量和质量。
- sing-box 绑定数量。
- 服务器文件描述符上限。
- CPU、内存和网络带宽。
- 上游代理本身的并发限制。

### 8.2 当前账号隔离

当前部署使用 `hybrid` 模式：旧静态共享账号继续可用，每个 Discord 登录用户首次打开仪表盘时会自动创建一个独立代理账号，不需要管理员预先分配。

当前实现遵循以下轻量边界：

- 所有用户继续连接同一个 `50089` 端口。
- 每个用户拥有独立用户名和随机密码。
- 多个用户共享同一个代理池和筛选能力。
- 用户可以自行查看和轮换自己的代理密码。
- 管理员可以创建、禁用、删除账号和轮换密码，但无需逐个分配。
- 账号变更不需要重启 ZenProxy。
- 不实现流量额度、计费、套餐、专属池或复杂权限。

应用代码仍支持 `ZENPROXY_PROXY_LISTENER_1` 至 `_10`，但独立账号统一使用同一个 `50089`，不需要“一用户一个端口”。

## 9. 动态绑定生命周期

每个出口节点可以拥有一个 sing-box 本地端口：

1. 如果节点已有绑定，直接复用。
2. 如果节点没有绑定，通过 sing-box Clash API 动态创建。
3. 使用计数 `in_flight` 在连接存活期间增加。
4. 连接关闭后减少使用计数并更新最后使用时间。
5. 非托管绑定空闲达到 `binding_idle_secs` 后删除。
6. 默认空闲时间为 300 秒。

该机制避免为代理库存中的所有节点永久占用端口。

需要关注：

- sing-box 最大动态绑定预算。
- 大量短连接带来的绑定创建压力。
- 同一热门出口被大量连接复用时的上游并发限制。
- 普通随机 Listener 连接失败不会像 Relay 一样立即回写失败状态；固定槽位会立即更换槽位映射，但节点全局有效性仍由验活任务维护。

## 10. 配置

`.env` 应包含：

```env
ZENPROXY_HOST_PORT=30595
ZENPROXY_PROXY_BIND_IP=0.0.0.0
ZENPROXY_PROXY_PORT=50089
ZENPROXY_PROXY_LISTENER=USER:STRONG_PASSWORD@0.0.0.0:1080
ZENPROXY_PROXY_AUTH_MODE=hybrid
ZENPROXY_PROXY_CREDENTIAL_SECRET=<至少 32 字节随机主密钥>
ZENPROXY_PUBLIC_PROXY_HOST=<公网 IP 或 DNS-only 域名>
ZENPROXY_PUBLIC_PROXY_PORT=50089
```

安全要求：

- 使用至少 24 字节随机密码。
- 密码不得包含会破坏 `user:pass@host:port` 格式的冒号或 `@`。
- `.env` 必须保持在 `.gitignore` 中。
- 修改旧静态共享账号需要重建容器；独立账号创建、禁用和轮换均即时生效。
- 不要把内部 Clash API `9090` 发布到公网。

应用也支持 `config.toml`：

```toml
[[proxy_listener]]
name = "default"
listen = "0.0.0.0:1080"
username = "USER"
password = "STRONG_PASSWORD"
```

环境变量存在时优先使用环境变量 Listener 配置。

## 11. UFW 与 Docker

当前防火墙策略：

- 默认拒绝入站。
- 默认拒绝路由转发。
- 默认允许出站。
- 放行 SSH `35586/tcp`。
- 放行 Web `80/tcp` 和 `443/tcp`。
- 放行代理入口 `50089/tcp`。
- 放行 Docker 转发目标 `1080/tcp`。

Docker 发布端口默认可能绕过 UFW 的 INPUT 规则，因此 `/etc/ufw/after.rules` 中加入了 `DOCKER-USER → ufw-user-forward` 集成。

检查命令：

```bash
ufw status verbose
iptables -S DOCKER-USER
iptables -L DOCKER-USER -n -v --line-numbers
ss -lntp | grep -E '50089|30595'
```

预期端口：

```text
0.0.0.0:50089      → ZenProxy 代理入口
127.0.0.1:30595    → ZenProxy Web API，仅供 Nginx
```

如果未来只允许固定业务机器使用，应同时收紧：

- UFW 的 `50089/tcp` INPUT 规则。
- UFW 的 `1080/tcp` routed 规则。

仅修改 INPUT 规则不足以限制 Docker 发布端口。

## 12. 运行验证

### 12.1 检查容器

```bash
docker compose ps zenproxy postgres
```

### 12.2 检查监听

```bash
ss -lntp | grep -E '50089|30595'
```

### 12.3 错误密码

错误密码应返回 HTTP 407：

```bash
curl --max-time 5 \
  -x "http://invalid:invalid@127.0.0.1:50089" \
  http://example.com/
```

### 12.4 正确密码

代理池存在有效节点时：

```bash
curl -x "http://USER:PASSWORD@127.0.0.1:50089" \
  https://httpbin.org/ip
```

代理池为空、筛选无匹配节点或三个候选都连接失败时，HTTP 模式通常返回 502。

### 12.5 验证轮换

确保客户端每次建立新连接：

```bash
for i in $(seq 1 5); do
  curl --no-keepalive \
    -x "http://USER:PASSWORD@127.0.0.1:50089" \
    https://httpbin.org/ip
done
```

结果可能重复，因为当前是随机选择而不是无重复轮询。

## 13. 常见故障

| 现象 | 常见原因 |
|---|---|
| `Connection refused` | Compose 未发布端口、容器未运行或监听地址错误 |
| HTTP 407 | 用户名或密码错误 |
| HTTP 502 | 代理池为空、筛选无匹配或候选节点连接失败 |
| 始终相同 IP | 客户端复用长连接、池中只有一个出口或多个节点共享出口 |
| 外网无法连接、localhost 正常 | UFW、云厂商安全组或运营商端口限制 |
| 域名连接失败、IP 正常 | 域名经过 Cloudflare；非标准 TCP 端口需 DNS-only |
| 节点失败但后台仍显示 Valid | Listener 失败尚未回写节点状态，等待后台验活 |
| 固定槽位显示待替换 | 同国家暂无满足原筛选条件的有效出口，等待订阅刷新或质检 |
| 大量连接后端口不足 | 动态绑定预算或文件描述符上限不足 |

## 14. 目标体验与当前差距

目标体验是“一个固定入口、多个独立账号、共享动态出口”，而不是商业代理平台：

```text
USER_A:PASSWORD_A ─┐
USER_B:PASSWORD_B ─┼→ SERVER:50089 → 共享代理池 → 动态出口
USER_C:PASSWORD_C ─┘
```

| 能力 | 当前状态 | 本项目目标 |
|---|---|---|
| 固定 host:port | 已实现 | 保持 |
| HTTP/SOCKS5 | 已实现 | 保持 |
| 新连接随机出口 | 已实现 | 保持 |
| 国家/住宅/协议筛选 | 已实现 | 保持 |
| 失败尝试其他出口 | 已实现 | 保持 |
| 多客户端共享并发 | 已实现 | 保持 |
| 单端口多个独立账号 | 已实现 | 保持 |
| 管理员创建、禁用账号 | 已实现 | 保持 |
| 单独轮换某个用户密码 | 已实现 | 保持 |
| 账号修改无需重启 | 已实现 | 保持 |
| 登录用户查看自己的账号 | 已实现 | 保持 |
| 参数选择与 URL 生成器 | 已实现 | 保持 |
| Session 固定 IP | 已实现 | 保持 |
| Session 指定间隔到期换 IP | 已实现 | 保持 |
| 定时轮换优先避免上一个 IP | 已实现 | 保持 |
| 固定槽位持续使用一个出口 | 已实现 | 保持 |
| 失效后自动补充同国家出口 | 已实现 | 保持 |
| 用户选择订阅槽位及导出链接 | 已实现 | 保持 |
| 严格每请求换 IP | 未实现 | 不作为账号改造前置条件 |

明确不在范围内：

- 流量额度和计费。
- 套餐、余额和到期计费逻辑。
- 每用户带宽整形。
- 用户专属代理池和独享出口。
- 复杂角色权限系统。
- 面向公开注册的商业用户中心。

## 15. 安全注意事项

- HTTP Proxy Basic 和 SOCKS5 用户名密码握手本身不加密。
- HTTPS 目标内容在 CONNECT 隧道中仍由目标 TLS 保护，但代理账号可能被链路观察者看到。
- 每个账号密码由服务端 HMAC-SHA256 主密钥、账号 ID 和凭据版本派生，不能使用简单人工密码。
- 数据库不保存明文密码或密码摘要，只保存 `credential_version`；主密钥仅保存在服务端环境变量中。
- 查看凭据接口必须返回 `Cache-Control: no-store`，前端不得把代理密码写入 localStorage。
- 固定订阅 Token 与代理密码独立派生和轮换；订阅响应使用 `Cache-Control: no-store`，完整链接按凭据管理。
- 日志不得记录密码、`Proxy-Authorization` 或完整代理 URL。
- 管理账号 API 只允许管理员访问。
- 如果使用者来源 IP 固定，仍建议通过 UFW 收紧 `50089` 和 Docker routed 规则。
- 不应把 PostgreSQL、Web API 内部端口或 Clash API 直接发布到公网。
- 上游代理的实际住宅属性、稳定性和合法使用范围取决于导入的节点来源。

## 16. 轻量多账号实现

### 16.1 设计目标

- 保持唯一公网入口 `SERVER:50089`。
- 每个使用者拥有独立用户名和密码。
- 登录用户首次访问时自动创建账号，无需管理员分配。
- 所有账号默认共享当前代理池。
- 继续支持国家、住宅、ChatGPT、Google 和协议筛选后缀。
- 多个账号可以同时并发使用，不做人为并发限制。
- 管理员可以创建、禁用、删除账号和轮换密码。
- 账号变更即时生效，不需要重启容器。
- 不复用 Discord API Key，代理凭据与 Web/API 凭据隔离。

### 16.2 数据表

独立的 `proxy_accounts` 表可选绑定一个现有 Discord 用户：

```sql
CREATE TABLE proxy_accounts (
    id              TEXT PRIMARY KEY,
    label           TEXT NOT NULL,
    username        TEXT NOT NULL UNIQUE,
    owner_user_id   TEXT UNIQUE REFERENCES users(id) ON DELETE SET NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    credential_version INTEGER NOT NULL DEFAULT 1,
    last_used_at    TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
```

字段说明：

- `label`：方便管理员识别账号属于哪台机器或哪个使用者。
- `username`：稳定且唯一，建议格式为 `zp_` 加随机短 ID。
- `owner_user_id`：自动账号固定为当前登录用户；管理员手工创建的账号可暂不绑定。
- `enabled`：用于立即停用账号。
- `credential_version`：轮换时递增；旧版本密码随即失效。
- `last_used_at`：只用于简单排障，不做流量统计或计费。

用户名限制为 `[A-Za-z0-9_]{3,32}`，不允许连字符。这样可以安全地把第一个 `-` 之后的内容作为筛选后缀解析。

### 16.3 凭据生成与保存

服务端使用以下公式稳定派生密码：

```text
password = Base64URL_NoPad(HMAC-SHA256(
  ZENPROXY_PROXY_CREDENTIAL_SECRET,
  account_id + ":" + credential_version
))
```

因此数据库无需保存密码，管理员和账号所有者仍可通过受保护接口重新显示当前连接信息。轮换只需原子递增 `credential_version`，旧密码会立即失效。更换主密钥会同时让全部独立账号失效，应当把主密钥作为长期部署密钥备份，且不得输出到日志。

### 16.4 Listener 认证流程

每个新连接：

1. 从 HTTP Basic 或 SOCKS5 认证中读取用户名和密码。
2. 从用户名中拆分基础账号与筛选后缀。
3. 从用户自动创建或管理员操作同步维护的内存缓存查询基础账号。
4. 检查账号是否存在并且 `enabled = true`。
5. Base64URL 解码提交的密码，并使用 HMAC 的常量时间校验验证。
6. 合并用户名中的筛选后缀。
7. 进入现有随机选点和 sing-box 绑定流程。
8. 认证通过后以最多每 60 秒一次的频率更新 `last_used_at`。

账号缓存使用 `DashMap`，管理 API 在数据库写入成功后同步替换或删除缓存，保证禁用、删除和轮换对新连接立即生效。`last_used_at` 最多每 60 秒写入一次，避免高并发短连接造成数据库写放大。

多个账号之间不需要独立连接计数；现有 Tokio 每连接异步任务可以自然支持并发。

### 16.5 API

用户接口使用现有 Discord Session，只能访问自己的账号；首次调用 `GET` 时会自动创建账号：

```text
GET  /api/proxy-access
POST /api/proxy-access/reveal
POST /api/proxy-access/rotate-password
```

管理员接口继续使用管理员 Bearer 密钥：

```text
GET    /api/admin/proxy-accounts
POST   /api/admin/proxy-accounts
PATCH  /api/admin/proxy-accounts/:id
DELETE /api/admin/proxy-accounts/:id
POST   /api/admin/proxy-accounts/:id/rotate-password
POST   /api/admin/proxy-accounts/:id/reveal
```

行为：

- `POST` 创建账号并返回当前派生密码。
- `GET` 返回账号、标签、绑定用户、启用状态和最后使用时间，不返回密码。
- `PATCH` 修改标签、绑定用户或启用状态。
- `DELETE` 删除不再使用的账号并清理认证缓存。
- `rotate-password` 递增凭据版本并立即让旧密码失效。
- `reveal` 重新派生当前密码，响应禁止缓存。

管理后台已增加轻量“固定入口代理账号”区域，不包含套餐、账单或用量页面。

### 16.6 兼容迁移

认证与公开入口由以下环境变量配置：

```dotenv
ZENPROXY_PROXY_AUTH_MODE=hybrid
ZENPROXY_PROXY_CREDENTIAL_SECRET=<至少 32 字节随机主密钥>
ZENPROXY_PUBLIC_PROXY_HOST=<公网 IP 或 DNS-only 域名>
ZENPROXY_PUBLIC_PROXY_PORT=50089
```

迁移顺序：

1. 增加数据表和数据库访问层。
2. Listener 使用 `hybrid`，让旧 `.env` 静态账号和数据库账号同时有效。
3. 用户首次打开仪表盘时自动创建独立账号。
4. 用户选择协议、国家、上游类型和能力标签，复制生成的连接信息；管理员只处理异常管理。
5. 验证多个账号能同时通过 `50089` 使用。
6. 通知旧客户端替换凭据。
7. 确认迁移完成后切换为 `accounts` 或 `database`，删除共享静态账号。

迁移过程中公网地址和端口不变。

### 16.7 前端 URL 生成器

用户仪表盘中的“固定入口 · 动态出口”区域提供：

- HTTP 或 `socks5h` 协议。
- 随机国家或指定国家。
- 随机上游类型或指定类型。
- Residential、ChatGPT、Google 能力组合。
- 每个新连接随机，或按 1～86400 秒的 Session 间隔轮换。
- 随机生成或自定义 Session ID，让同一账号的多个业务独立轮换。
- 完整 URL、`HOST:PORT:USER:PASS`、`USER:PASS@HOST:PORT`、curl 和环境变量/JSON 格式。

用户名和密码在 URL 中使用 `encodeURIComponent` 编码。页面初始不读取密码，用户主动点击显示后才请求 `reveal`；刷新或点击隐藏后密码从页面变量中移除。

### 16.8 后续可选能力

账号功能稳定后再考虑：

1. 把定时 Session 持久化，使服务重启后仍延续原周期。
2. Listener 连接失败回写节点状态。
3. 更清晰的连接和握手超时。

这些能力与独立账号解耦，不阻塞多账号上线。

### 16.9 明确不实施

- 每用户流量额度。
- 请求计费和账单。
- 套餐与余额。
- 每用户限速。
- 每日流量统计报表。
- 专属池、独享 IP 和复杂权限。
- 公开注册和用户自助购买。

## 17. 固定出口实现维护

### 17.1 持久化结构

`fixed_proxy_slots` 保存账号拥有的槽位、稳定 `slot_key`、原国家、替换筛选条件、当前 `proxy_id`/出口 IP、订阅勾选及最近替换信息。`proxy_id` 故意不建立外键：上游订阅或验活流程可以正常删除代理行，槽位巡检随后检测缺失并同区补位。

同一账号通过 `(account_id, exit_ip)` 唯一约束避免多个槽位指向同一真实出口。账号删除时槽位通过 `account_id` 外键级联删除。

`fixed_proxy_subscriptions` 只保存账号的 Token 版本，不保存明文 Token。Token 使用主密钥、账号 ID 和版本通过 HMAC-SHA256 派生，轮换版本即可让旧链接失效。

### 17.2 用户 API

管理接口支持 Discord Session 或 API Key Bearer，且始终根据认证用户解析自己的代理账号：

```text
GET    /api/fixed-exits
POST   /api/fixed-exits
POST   /api/fixed-exits/pin
PATCH  /api/fixed-exits/:id
POST   /api/fixed-exits/:id/replace
DELETE /api/fixed-exits/:id
POST   /api/fixed-exits/subscription/rotate-token
```

固定订阅是持有 Token 即可访问的只读端点：

```text
/fixed-sub/{account_id}/{token}/clash-http.yaml
/fixed-sub/{account_id}/{token}/clash-socks5.yaml
/fixed-sub/{account_id}/{token}/http.txt
/fixed-sub/{account_id}/{token}/socks5.txt
```

所有固定订阅响应均使用 `Cache-Control: no-store`。代理密码轮换不会修改订阅链接，但客户端需要刷新订阅以取得新密码；订阅 Token 轮换不影响固定槽位 URL。

### 17.3 自动替换并发语义

请求首先尝试槽位当前出口。需要替换时以槽位 ID 获取 Tokio 锁，并在持锁后重新读取数据库；如果其他请求或后台任务已经完成替换，就直接复用新映射。否则从同国家且满足原条件的唯一出口中选择候选，真实连接成功后才更新槽位。

后台巡检和请求时切换共用相同槽位锁。后台可以根据已有验活/质量结果提前修复；请求路径负责最后一道真实连接故障切换。替换只影响随后建立的新连接，不中断旧连接。

### 16.10 验收标准

- 两个以上独立账号可以同时连接 `50089`。
- 新登录用户无需管理员操作即可自动获得并使用独立账号。
- 不同账号密码互不通用。
- 账号筛选后缀继续正常工作。
- 禁用账号后，新连接立即返回认证失败。
- 密码轮换后，旧密码立即失效，新密码可用。
- 创建、禁用、删除和轮换账号不需要重启 ZenProxy。
- 旧共享账号在 `hybrid` 迁移阶段仍然可用。
- 数据库、日志和 API 列表不出现明文密码；只有显式 reveal/create/rotate 响应包含当前密码且禁止缓存。
- 用户生成器使用显式配置的公网地址，不从 Cloudflare Web 域名推断入口。
- 同一账号的普通随机 URL 和定时轮换 URL 可以同时使用，状态互不干扰。
- 定时 Session 在到期前的多条新连接使用同一出口，到期后优先切换到不同 IP。
- 不增加流量额度、计费或复杂用户权限逻辑。

## 17. 相关代码

| 文件 | 职责 |
|---|---|
| `src/proxy_listener.rs` | HTTP/SOCKS5 入口、认证、筛选、连接转发 |
| `src/proxy_account.rs` | 用户名校验、HMAC 密码派生与常量时间验证 |
| `src/proxy_rotation.rs` | 定时 Session 状态、并发锁、闲置清理和安全边界 |
| `src/api/proxy_access.rs` | 用户/管理员代理账号 API 与公网入口元数据 |
| `src/web/user.html` | 用户参数选择与多格式 URL 生成器 |
| `src/web/admin.html` | 代理账号创建、绑定、启停、查看和轮换 |
| `src/api/fetch.rs` | 随机有效节点选择入口 |
| `src/db.rs` | 有效节点过滤、出口去重和随机 SQL |
| `src/bindings.rs` | sing-box 动态绑定、使用计数和空闲清理 |
| `src/config.rs` | Listener 环境变量和配置解析 |
| `src/singbox/process.rs` | sing-box 进程和动态绑定 API |
| `compose.yml` | 公网端口、容器端口和环境变量 |
| `config.toml.example` | Listener 与绑定生命周期示例配置 |

修改固定入口模式时，应同步检查：

- Listener 协议行为。
- 数据库选点语义。
- 动态绑定生命周期。
- Compose 端口映射。
- UFW 的 INPUT、routed 和 DOCKER-USER 规则。
- README 和本文档。
