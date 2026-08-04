# Proxy

Proxy 是一个代理池管理与转发服务，由两部分组成：

- **Proxy Server**（Rust + Axum）：服务端，管理代理池、用户认证、请求转发、代理验证与质检
- **sing-box-zenproxy**（Go，修改版 sing-box）：本地客户端，通过 Clash API 提供代理存储、订阅管理、批量绑定等功能，支持并发多 IP 出口

## 架构概览

### 服务端模式

```
用户请求 → Proxy Server (Axum) → sing-box (动态 Bindings) → 代理服务器 → 目标网站
```

### 本地客户端模式

```
你的程序 → 127.0.0.1:20001 ──→ 代理A (IP-A)
         → 127.0.0.1:20002 ──→ 代理B (IP-B)
         → 127.0.0.1:20003 ──→ 代理C (IP-C)
         ...
         → 127.0.0.1:20100 ──→ 代理N (IP-N)

代理来源：
  ├── 从 Proxy Server 批量 fetch
  ├── 从订阅 URL 导入
  └── 手动添加 URI / outbound JSON
```

每个本地端口是独立的 HTTP+SOCKS5 代理，路由到不同出口 IP。端口池范围 20001-30000，最多同时绑定 10000 个代理。适用于批量注册、数据采集等需要并发多 IP 的场景。

---

## 一、Proxy Server（Rust 服务端）

### 支持的代理协议

- VMess
- VLESS
- Trojan
- Shadowsocks
- Hysteria2
- SOCKS5 / SOCKS4
- HTTP / HTTPS

### 支持的订阅格式

| 类型 | 说明 |
|------|------|
| `auto` | 自动检测（默认），依次尝试 Clash YAML → Base64 V2Ray → 原始 V2Ray URI |
| `clash` | Clash YAML 格式（`proxies:` 字段） |
| `v2ray` | V2Ray URI 格式，每行一个 `vmess://`、`vless://`、`trojan://`、`socks5://`、`http://` 等 |
| `base64` | Base64 编码的 V2Ray URI 列表 |
| `socks5` | 纯文本 SOCKS5 代理列表，每行 `host:port` 或 `user:pass@host:port` |
| `socks4` | 纯文本 SOCKS4 代理列表，格式同上 |
| `http` | 纯文本 HTTP 代理列表，格式同上 |
| `https` | 纯文本 HTTPS 代理列表，格式同上（启用 TLS） |

### 配置文件

Proxy 从 `config.toml` 读取配置（与可执行文件同目录）。仓库只提交 `config.toml.example`，使用前先复制为 `config.toml`：

```bash
cp config.toml.example config.toml
```

示例：

```toml
[server]
host = "0.0.0.0"
port = 3000
admin_password = "change-me"              # 管理后台密码

[oauth]
client_id = "your-discord-client-id"      # Discord OAuth client ID
client_secret = "your-discord-client-secret"
redirect_uri = "https://proxy.example.com/api/auth/callback"
required_guild_id = "your-discord-guild-id"

[singbox]
binary_path = "/usr/local/bin/sing-box"   # sing-box 二进制路径（同目录优先）
config_path = "data/singbox-config.json"  # sing-box 运行配置路径（自动生成）
base_port = 10001
max_proxies = 20000
prebound_proxies = 500
binding_idle_secs = 300

[database]
url = "postgresql://postgres:change-me@127.0.0.1:5432/zenproxy"

[validation]
url = "https://www.gstatic.com/generate_204"
fallback_url = "https://cp.cloudflare.com/generate_204"
timeout_secs = 10
concurrency = 200
interval_mins = 30
error_threshold = 10
max_rounds_per_run = 20
retry_invalid_per_run = 500
batch_size = 300
valid_recheck_hours = 24
new_proxy_percent = 70
valid_recheck_percent = 20
invalid_retry_percent = 10
binding_failure_threshold = 3

[quality]
interval_mins = 180
concurrency = 10
stale_hours = 72
max_checks_per_run = 200

[relay]
timeout_secs = 600

[subscription]
password = "change-subscription-password" # 订阅下载密码（请与管理密码不同）
auto_refresh_interval_mins = 1440          # URL 订阅每天无人值守自动刷新
orphaned_valid_grace_hours = 24
export_cache_secs = 60

# 也可通过环境变量配置: ZENPROXY_PROXY_LISTENER=myuser:mypass@0.0.0.0:1080
# [[proxy_listener]]
# name = "default"
# listen = "0.0.0.0:1080"
# username = "myuser"
# password = "mypassword"
```

### 认证方式

| 方式 | 适用场景 | 格式 |
|------|----------|------|
| OAuth 会话 | Web 页面 | Cookie: `zenproxy_session=...`（7 天有效） |
| API Key | 程序调用 | Query: `?api_key=xxx` 或 Header: `Authorization: Bearer xxx` |
| 管理密码 | 管理后台 | Header: `Authorization: Bearer {admin_password}` |
| 订阅密码 | 下载客户端订阅 | URL path: `/sub/{subscription_password}/...` |

OAuth 使用 Discord 作为身份提供商。用户必须已加入 `oauth.required_guild_id` 指定的服务器，登录后才会获得 API Key。

> **注意：** `/api/relay` 端点**仅支持 `api_key` query 参数认证**。请求中的 `Authorization`、`Cookie` 等 header 会原样转发给目标服务器。

### 服务端 API

#### 页面

| 路径 | 说明 |
|------|------|
| `GET /` | 用户页面 |
| `GET /admin` | 管理后台 |
| `GET /docs` | API 文档 |

#### 认证

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| `GET /api/auth/login` | 跳转 OAuth 登录 | 无 |
| `GET /api/auth/callback` | OAuth 回调 | 无 |
| `GET /api/auth/me` | 获取当前用户信息 | 会话 |
| `POST /api/auth/logout` | 登出 | 会话 |
| `POST /api/auth/regenerate-key` | 重新生成 API Key | 会话 |

#### 代理获取（/api/fetch）

```
GET /api/fetch?api_key=xxx&count=5&country=US&chatgpt=true
```

**参数：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `api_key` | string | - | API Key（也可用 Header） |
| `count` | int | 1 | 返回代理数量 |
| `proxy_id` | string | - | 指定代理 ID |
| `chatgpt` | bool | false | 仅返回支持 ChatGPT 的代理 |
| `google` | bool | false | 仅返回支持 Google 的代理 |
| `residential` | bool | false | 仅返回住宅 IP 代理 |
| `risk_max` | float | - | 最大风险评分（0~1） |
| `country` | string | - | 国家代码过滤（如 US、JP） |
| `type` | string | - | 代理类型过滤（vmess、vless、trojan 等） |

**响应示例：**

```json
{
  "proxies": [
    {
      "id": "uuid",
      "name": "代理名称",
      "type": "vmess",
      "server": "1.2.3.4",
      "port": 443,
      "local_port": 10002,
      "status": "valid",
      "quality": {
        "ip_address": "5.6.7.8",
        "country": "US",
        "ip_type": "ISP",
        "is_residential": true,
        "chatgpt": true,
        "google": true,
        "risk_score": 0.1,
        "risk_level": "Low"
      }
    }
  ],
  "count": 1
}
```

#### 客户端专用获取（/api/client/fetch）

供本地客户端使用，返回代理信息 **含完整 outbound 配置**，可直接用于 sing-box 创建绑定。

```
GET /api/client/fetch?api_key=xxx&count=100&country=US&type=vmess
```

参数同 `/api/fetch`，默认 `count=10`。

**响应示例：**

```json
{
  "proxies": [
    {
      "id": "uuid",
      "name": "proxy-name",
      "type": "vmess",
      "server": "1.2.3.4",
      "port": 443,
      "outbound": {
        "type": "vmess",
        "server": "1.2.3.4",
        "server_port": 443,
        "uuid": "...",
        "alter_id": 0,
        "security": "auto"
      },
      "quality": {
        "country": "US",
        "chatgpt": true,
        "google": true,
        "is_residential": false,
        "risk_score": 0.1,
        "risk_level": "Low"
      }
    }
  ],
  "count": 1
}
```

#### 请求转发（/api/relay）

通过代理池转发任意 HTTP 请求到目标 URL。

```
POST /api/relay?api_key=xxx&url=https://api.example.com/data&method=POST&country=US
```

> **认证要求：** relay 端点**仅接受 `api_key` query 参数**认证。请求中的 `Authorization`、`Cookie` 等 header 会原样转发给目标。

**参数：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `url` | string | **必填** | 目标 URL |
| `method` | string | GET | HTTP 方法（GET/POST/PUT/DELETE/PATCH/HEAD） |
| `api_key` | string | **必填** | Proxy API Key（仅支持 query 参数） |
| `proxy_id` | string | - | 指定代理（支持无端口代理，按需创建绑定） |
| `chatgpt` | bool | false | ChatGPT 可用过滤 |
| `google` | bool | false | Google 可用过滤 |
| `residential` | bool | false | 住宅 IP 过滤 |
| `risk_max` | float | - | 最大风险评分 |
| `country` | string | - | 国家过滤 |
| `type` | string | - | 代理类型过滤 |

> **超时说明：** `/api/relay` 默认总超时为 `600` 秒，可通过 `config.toml` 的 `relay.timeout_secs` 调整；设为 `0` 可关闭总超时。

**额外响应头：**

| Header | 说明 |
|--------|------|
| `X-Proxy-Id` | 使用的代理 ID |
| `X-Proxy-Name` | 代理名称（URL 编码） |
| `X-Proxy-Server` | 代理服务器地址 |
| `X-Proxy-IP` | 代理出口 IP |
| `X-Proxy-Country` | 代理所在国家 |
| `X-Proxy-Attempt` | 重试次数（仅随机选择时） |

**使用示例：**

```bash
# 通过美国住宅代理访问 API
curl "https://proxy.mui.moe/api/relay?api_key=xxx&url=https://httpbin.org/ip&country=US&residential=true"

# 通过指定代理发送 POST 请求
curl -X POST "https://proxy.mui.moe/api/relay?api_key=xxx&url=https://api.example.com/data&method=POST&proxy_id=uuid" \
  -H "Authorization: Bearer target_api_token" \
  -H "Content-Type: application/json" \
  -d '{"key": "value"}'
```

#### 代理池监听端口（Proxy Pool Listener）

> 维护文档：[固定入口、动态出口模式](docs/fixed-entry-dynamic-exit.md)

zenproxy 可以作为标准的 SOCKS5 / HTTP 代理服务器使用，每个新 TCP 连接自动从代理池随机选择一个节点。单个端口同时支持 SOCKS5 和 HTTP CONNECT（自动检测），并可让多个独立账号自然并发使用同一个共享代理池。

迁移期推荐保留静态共享账号并同时启用独立账号：

```env
ZENPROXY_PROXY_AUTH_MODE=hybrid
ZENPROXY_PROXY_CREDENTIAL_SECRET=<openssl rand -hex 32>
ZENPROXY_PUBLIC_PROXY_HOST=<服务器公网 IP 或 DNS-only 域名>
ZENPROXY_PUBLIC_PROXY_PORT=50089
```

每个 Discord 用户首次打开仪表盘时会自动获得独立代理账号，无需管理员分配。用户可直接选择协议、国家、上游类型和能力标签并复制多种格式的代理 URL；管理员只需在 `/admin` 处理启停、轮换和排障。数据库不保存代理明文密码。

**配置方式（二选一）：**

环境变量（推荐，格式 `user:pass@host:port`）：

```env
ZENPROXY_PROXY_LISTENER=myuser:mypass@0.0.0.0:1080
```

或 `config.toml`：

```toml
[[proxy_listener]]
name = "default"
listen = "0.0.0.0:1080"
username = "myuser"
password = "mypassword"
```

> 支持多个 listener：`ZENPROXY_PROXY_LISTENER_1`、`ZENPROXY_PROXY_LISTENER_2`、…（最多 10 个）

**鉴权格式：** 标准代理鉴权（SOCKS5 用户名密码 / HTTP Proxy-Authorization Basic）

**代理过滤：** 通过用户名后缀动态指定过滤条件，格式为 `{base_user}-{key}-{value}-{flag}`：

| 后缀 | 说明 | 示例 |
|------|------|------|
| `-country-XX` | 指定国家代码 | `myuser-country-US` |
| `-residential` | 仅住宅 IP | `myuser-residential` |
| `-chatgpt` | ChatGPT 可访问 | `myuser-chatgpt` |
| `-google` | Google 可访问 | `myuser-google` |
| `-type-TYPE` | 指定代理类型 | `myuser-type-vmess` |
| `-session-ID-rotate-SECONDS` | 指定时间内固定出口，到期轮换 | `myuser-session-crawler_01-rotate-300` |
| `-fixed-SLOT` | 使用已申请的固定出口槽位 | `zp_xxx-fixed-f123abc` |

后缀可自由组合：`myuser-country-US-residential-chatgpt`

**使用示例：**

```bash
# SOCKS5 — 随机代理
curl -x socks5://myuser:mypass@proxy.example.com:1080 https://httpbin.org/ip

# SOCKS5 — 美国住宅代理
curl -x socks5://myuser-country-US-residential:mypass@proxy.example.com:1080 https://httpbin.org/ip

# HTTP CONNECT — ChatGPT 可用代理
curl -x http://myuser-chatgpt:mypass@proxy.example.com:1080 https://httpbin.org/ip

# HTTP CONNECT — crawler_01 在 5 分钟内固定出口，到期后换 IP
curl -x http://myuser-session-crawler_01-rotate-300:mypass@proxy.example.com:1080 https://httpbin.org/ip

# HTTP CONNECT — 使用数据库账号已申请的固定出口槽位
curl -x http://zp_xxx-fixed-f123abc:mypass@proxy.example.com:1080 https://httpbin.org/ip

# 多次请求验证 IP 轮换
for i in $(seq 1 5); do
  curl -s -x socks5://myuser:mypass@proxy.example.com:1080 https://httpbin.org/ip
done
```

Session ID 限制为 1～32 个字母、数字或下划线，间隔支持 1～86400 秒。不带定时后缀的 URL 仍按每个新 TCP 连接随机出口；同一账号可以同时使用普通随机 URL 和多个独立的定时 Session URL。已建立的长连接不会在中途切换 IP。

固定出口槽位由登录用户在仪表盘自行申请，旧静态 Listener 账号不能伪造或使用数据库槽位。槽位正常时持续使用同一个已测出口 IP；出口失效、被上游订阅移除、出口 IP 或国家变化时，系统只从槽位原国家选择替代出口。槽位用户名保持不变，且不会跨国家回退。

> **重试机制：** 连接失败时自动重试最多 3 个不同的代理节点。

> **Docker 部署：** `compose.yml` 已包含代理端口映射。在 `.env` 中设置 `ZENPROXY_PROXY_PORT`（远程客户端连接的宿主机端口）和 `ZENPROXY_PROXY_LISTENER=user:strong-password@0.0.0.0:1080` 即可。容器内端口固定为 1080，避免与宿主机上其他服务的端口冲突。

#### 固定出口管理与订阅

固定出口管理接口接受登录会话或 `Authorization: Bearer {api_key}`，每个账号最多保存 50 个槽位（技术安全上限，不涉及计费或额度）：

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET /api/fixed-exits` | 查看自己的槽位和订阅链接 |
| `POST /api/fixed-exits` | 按国家、类型和质量条件批量申请 |
| `POST /api/fixed-exits/pin` | 把指定 `proxy_id` 加入固定槽位 |
| `PATCH /api/fixed-exits/:id` | 修改名称或是否加入订阅 |
| `POST /api/fixed-exits/:id/replace` | 手动更换同国家出口 |
| `DELETE /api/fixed-exits/:id` | 删除槽位 |
| `POST /api/fixed-exits/subscription/rotate-token` | 轮换固定订阅 Token |

批量申请示例：

```bash
curl -X POST https://proxy.mui.moe/api/fixed-exits \
  -H "Authorization: Bearer <api_key>" \
  -H "Content-Type: application/json" \
  -d '{"count":10,"country":"US","residential":false}'
```

每个账号会生成四种独立订阅地址：Clash HTTP、Clash SOCKS5、HTTP URL 列表和 SOCKS5 URL 列表。订阅只包含用户勾选的槽位，只暴露统一网关及槽位凭据，不包含真实上游节点配置。订阅 Token 可以单独轮换；代理密码轮换后，重新刷新原订阅链接即可获得新密码。

#### 代理列表（/api/proxies）

```
GET /api/proxies?api_key=xxx
```

返回所有代理及统计信息，包含质检数据。

#### 客户端订阅（/sub）

订阅链接只返回已验活且仍属于当前订阅源的代理，并使用独立的 `subscription.password` 鉴权。该密码只用于订阅下载 URL，不能访问管理接口。也可通过 `ZENPROXY_SUBSCRIPTION_PASSWORD` 设置；旧配置未设置时暂时回退到 `server.admin_password`，升级后建议立即补上独立密码。

```
https://proxy.mui.moe/sub/{subscription_password}/all/clash.yaml
https://proxy.mui.moe/sub/{subscription_password}/vless/clash.yaml
https://proxy.mui.moe/sub/{subscription_password}/vmess/clash.yaml
https://proxy.mui.moe/sub/{subscription_password}/trojan/clash.yaml
```

`all` 返回全部已支持的真实代理节点；也可以使用 `vless`、`vmess`、`trojan`、`shadowsocks`、`hysteria2`、`socks`、`http` 按协议筛选。默认输出只含顶层 `proxies` 节点列表的 Clash YAML，不包含 `proxy-groups`、`rules`、`direct`、`reject` 等策略或特殊类型，方便导入其他软件；`/clash.yaml` 后缀用于显式区分客户端格式。

服务端会在验证、刷新订阅、删除代理或 relay 将代理降级时清空订阅缓存；平时生成结果按 `[subscription] export_cache_secs` 缓存，默认 60 秒，设为 0 表示每次实时生成。

#### 管理接口

所有管理接口需要 `Authorization: Bearer {admin_password}`。

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET /api/admin/stats` | 系统统计 |
| `GET /api/admin/proxies` | 代理列表 |
| `DELETE /api/admin/proxies/:id` | 删除代理 |
| `POST /api/admin/proxies/cleanup` | 清理高错误代理 |
| `POST /api/admin/validate` | 手动触发验证 |
| `POST /api/admin/quality-check` | 手动触发质检 |
| `GET /api/admin/jobs` | 查询验活/质检任务范围、阶段和实时进度 |
| `GET /api/admin/users` | 用户列表 |
| `DELETE /api/admin/users/:id` | 删除用户 |
| `POST /api/admin/users/:id/ban` | 封禁用户 |
| `POST /api/admin/users/:id/unban` | 解封用户 |
| `GET /api/subscriptions` | 列出所有订阅 |
| `POST /api/subscriptions` | 添加订阅 |
| `DELETE /api/subscriptions/:id` | 删除订阅及其代理 |
| `POST /api/subscriptions/:id/refresh` | 刷新订阅 |
| `POST /api/subscriptions/:id/validate` | 强制验活指定订阅的全部节点 |
| `POST /api/subscriptions/:id/quality-check` | 强制质检指定订阅的有效节点（包含解锁检测） |

### 验证与质检

`[quality] interval_mins` 控制后台质检轮询周期（设为 `0` 关闭自动质检），`stale_hours` 控制旧质检结果多久后标记为过期并重新检查，`max_checks_per_run` 限制每轮数量。管理面板的手动质检仍会立即触发。

#### 代理验证（Validation）

验证通过配置的主、备用 URL 检测代理是否可用；两个地址都只接受精确的 HTTP 204，并正常校验 TLS 证书。主地址失败后才尝试备用地址。

对外获取、Relay/监听器自动选点以及 Clash 订阅都按质检得到的出口 IP 去重；同一出口 IP 只保留错误更少、最近验活成功的一条线路。尚未获得出口 IP 的节点留在内部库存继续质检，但不会提前出现在对外结果中。ChatGPT、Google、住宅和质检统计也按唯一出口 IP 计数。

**触发时机：**
- 导入/刷新订阅后**立即触发**
- 定时任务：每 `validation.interval_mins` 分钟运行一次
- 定时订阅刷新后自动触发（需开启 `auto_refresh_interval_mins`）
- 管理后台“全局验活队列”消费当前待检测、到期复验和冷却重试队列
- 订阅行的“验活”会忽略上次验活时间，强制检查该订阅的全部不同代理配置

**流程：**
1. 每轮按 `new_proxy_percent` / `valid_recheck_percent` / `invalid_retry_percent` 分配新节点、到期有效节点、冷却后的无效节点名额，避免任一队列长期饿死
2. 有效节点超过 `valid_recheck_hours` 后重新验证；设为 `0` 可关闭这类周期复验
3. `sync_proxy_bindings(Validation)` 为本轮候选分配临时端口并并发探测
4. 成功 → Valid（error_count 清零），失败 → Invalid
5. sing-box 绑定失败独立计数且有冷却，不会立即删除；达到 `binding_failure_threshold` 才淘汰
6. 达到 `max_rounds_per_run` 后暂停，下一次定时任务继续处理
7. 验证完成后执行 `sync_proxy_bindings(Normal)` 恢复正常端口分配

**Relay 失败反馈：** 用户通过 `/api/relay` 使用代理失败时，该代理的 `error_count` 会自动增加并进入待重试状态。为避免短时网络抖动反复占用端口，失败节点冷却 3 小时后才会进入无效节点复验队列。

#### 订阅自动刷新

在 `config.toml` 中设置 `[subscription] auto_refresh_interval_mins = 1440` 即可每天无人值守刷新；设为 `0` 才会关闭。单个订阅设置了独立刷新周期时，以单个订阅为准。URL 订阅刷新完成后会自动进入验活，不需要点击后台按钮。

**刷新策略（平滑替换）：**
- 拉取/解析失败时，旧代理**完全不受影响**
- 解析出 0 个代理时，中止刷新，保留旧数据
- 对 (server, port, proxy_type) 及完整 outbound 配置都相同的代理，保留验证状态、端口绑定和质检数据
- 如果端点相同但密码、UUID、传输或 TLS 等 outbound 配置变化，清理旧绑定/质检并重新验活
- 仅新增的代理标记为 Untested 等待验证
- 仅已消失的旧代理才会被删除
- 全部刷新完成后统一触发一次验证

#### 质量检测（Quality Check）

验活通过后会自动探测并保存出口 IP。质量检测优先使用 IPPure 获取 IP、ASN、地理位置、欺诈分、住宅/机房及原生/广播属性；IPPure 省略字段或暂时不可用时，再由 ip-api.com 和 ipinfo.io 补齐。公共代理接口和 Clash 订阅会按出口 IP 自动去重，同一出口只返回状态最佳的一条节点，无需手动维护。

**检测内容：**
| 项目 | 来源 | 说明 |
|------|------|------|
| IP 地址、ASN、地区 | IPPure（优先） | 代理出口及运营商信息 |
| 风险、住宅/机房、原生/广播 | IPPure（优先） | `fraudScore` 转换为 0-1 风险系数 |
| IP/国家/IP 类型补充 | ip-api.com / ipinfo.io | IPPure 缺少字段时回退 |
| ChatGPT 可访问 | chatgpt.com / ios.chat.openai.com | 区分不可用和仅 Web 可用 |
| Google 可访问 | google.com/generate_204 | 检测连通性 |
| 扩展解锁 | Sora / Gemini / Copilot / Claude / Netflix / YouTube Premium / Spotify / TikTok | 保存可用状态、地区和判定详情 |

扩展结果保存在质量对象的 `details.ip` 和 `details.unlock` 字段中，用户及管理后台的代理质量表可以直接展开查看。解锁结果是未登录状态下的地区与网络可达性探测，不代表账号、付费套餐或特定内容一定可用。

解锁检测不在基础验活中执行，而是质量检测的一部分。“全局到期质检”只检查尚未质检、结果不完整或已经过期的有效节点；订阅行的“解锁质检”会强制重测该订阅当前有效节点，即使已有结果仍在有效期内。管理后台每 1.5 秒读取 `/api/admin/jobs`，显示当前范围、检测阶段、完成数、成功数和失败数。

### 服务端部署

#### Docker Compose

Compose 内置 PostgreSQL，并将 ZenProxy Web API 仅发布到宿主机回环地址，供宿主机 Nginx 提供 HTTPS。标准 SOCKS5/HTTP 代理端口按 `.env` 中的 `ZENPROXY_PROXY_PORT` 单独发布；PostgreSQL 不向宿主机发布端口。

```bash
cp .env.example .env
# 编辑 .env：设置 ZENPROXY_HOST_PORT、强代理密码和公开代理端口
# 将 ZENPROXY_OAUTH_REDIRECT_URI 改为 https://proxy.example.com/api/auth/callback
docker compose up -d --build
```

#### 编译

```bash
# sing-box（修改版）
cd sing-box-zenproxy
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o sing-box -tags with_clash_api ./cmd/sing-box

# Proxy Server
cargo zigbuild --release --target x86_64-unknown-linux-gnu
```

#### 目录结构

```
/opt/zenproxy/
├── zenproxy          # Rust 主程序
├── sing-box          # 修改版 sing-box（同目录优先加载）
├── config.toml       # 配置文件
├── config.toml.example  # 配置模板
└── data/
    ├── zenproxy.db           # SQLite 数据库
    └── singbox-config.json   # 自动生成的 sing-box 配置
```

#### 启动

```bash
cd /opt/zenproxy
cp -n config.toml.example config.toml
./zenproxy
```

---

## 二、sing-box-zenproxy（本地客户端）

sing-box-zenproxy 是修改版 sing-box，在官方 Clash API 基础上新增了代理存储、订阅管理、远程 Fetch、批量绑定等功能，用于将 Proxy 的代理池能力搬到用户本地使用。

### 新增功能概览

| 功能 | 说明 |
|------|------|
| **代理存储** | 本地 JSON 文件持久化代理列表，重启不丢失 |
| **订阅管理** | 支持 V2Ray URI / Clash YAML / Base64 订阅格式 |
| **远程 Fetch** | 从 Proxy Server 批量获取代理 |
| **端口池** | 自动分配本地端口（20001-30000），无需手动指定 |
| **批量绑定** | 一键为所有代理创建本地 HTTP/SOCKS5 代理端口 |
| **协议解析器** | 内置 vmess/vless/trojan/ss/hy2 URI 和 Clash YAML 解析 |

### 架构

```
sing-box-zenproxy Clash API (默认 127.0.0.1:9090)
├── /store              代理存储 CRUD
├── /subscriptions      订阅管理
├── /fetch              从服务器 fetch 代理
├── /bindings           动态绑定管理（含批量）
│   ├── POST /batch     批量创建绑定
│   └── DELETE /all     删除所有绑定
└── data/store.json     持久化文件
```

### 新增源码结构

```
experimental/clashapi/
├── store.go           # 代理存储（ProxyStore），文件持久化
├── proxy_manage.go    # GET/POST/DELETE /store 端点 + PortPool
├── subscription.go    # 订阅管理端点
├── remote_fetch.go    # 从 Proxy Server fetch 代理
├── bindings.go        # 增强版绑定管理（proxy_id、batch、delete all）
├── server.go          # 路由注册（新增 /store、/fetch、/subscriptions）
└── parser/
    ├── parser.go      # 解析入口 + 自动检测
    ├── v2ray.go       # vmess/vless/trojan/ss/hy2 URI 解析
    ├── clash.go       # Clash YAML 解析
    └── base64.go      # Base64 解码
```

### 客户端 API

所有 API 通过 Clash API 地址访问（默认 `http://127.0.0.1:9090`），认证方式为 Bearer Token（sing-box 配置中的 `secret`）。

#### 代理存储（/store）

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET /store` | 列出所有存储的代理 |
| `POST /store` | 添加代理 |
| `DELETE /store/{id}` | 删除指定代理 |
| `DELETE /store` | 清空所有代理 |

**添加代理（URI 方式）：**

```bash
curl -X POST http://127.0.0.1:9090/store \
  -H "Authorization: Bearer your-secret" \
  -d '{"uri": "vmess://eyJhZGQiOi..."}'
```

**添加代理（outbound JSON 方式）：**

```bash
curl -X POST http://127.0.0.1:9090/store \
  -H "Authorization: Bearer your-secret" \
  -d '{
    "outbound": {
      "type": "vmess",
      "server": "1.2.3.4",
      "server_port": 443,
      "uuid": "xxx",
      "alter_id": 0,
      "security": "auto"
    }
  }'
```

**响应：**

```json
{
  "id": "generated-uuid",
  "name": "1.2.3.4:443",
  "type": "vmess",
  "server": "1.2.3.4",
  "port": 443,
  "outbound": { "type": "vmess", "..." },
  "source": "manual",
  "added_at": "2026-03-01T12:00:00Z"
}
```

#### 订阅管理（/subscriptions）

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET /subscriptions` | 列出所有订阅 |
| `POST /subscriptions` | 添加订阅 |
| `DELETE /subscriptions/{id}` | 删除订阅及其代理 |
| `POST /subscriptions/{id}/refresh` | 刷新订阅（重新获取并替换代理） |

**从 URL 添加订阅：**

```bash
curl -X POST http://127.0.0.1:9090/subscriptions \
  -H "Authorization: Bearer your-secret" \
  -d '{
    "name": "my-sub",
    "url": "https://example.com/sub",
    "type": "auto"
  }'
```

**直接提供内容：**

```bash
curl -X POST http://127.0.0.1:9090/subscriptions \
  -H "Authorization: Bearer your-secret" \
  -d '{
    "name": "manual-sub",
    "type": "v2ray",
    "content": "vmess://...\nvless://..."
  }'
```

**响应：**

```json
{
  "subscription": {
    "id": "sub-uuid",
    "name": "my-sub",
    "type": "auto",
    "url": "https://example.com/sub",
    "proxy_count": 50,
    "created_at": "...",
    "updated_at": "..."
  },
  "added": 50
}
```

#### 远程 Fetch（/fetch）

从 Proxy Server 批量获取代理（含 outbound 配置），存入本地。

```bash
curl -X POST http://127.0.0.1:9090/fetch \
  -H "Authorization: Bearer your-secret" \
  -d '{
    "server": "https://proxy.mui.moe",
    "api_key": "your-api-key",
    "count": 100,
    "country": "US",
    "type": "vmess",
    "auto_bind": false
  }'
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `server` | string | **必填** | Proxy Server 地址 |
| `api_key` | string | **必填** | Proxy 用户 API Key |
| `count` | int | 10 | 获取代理数量 |
| `country` | string | - | 国家过滤 |
| `chatgpt` | bool | false | ChatGPT 可用过滤 |
| `type` | string | - | 代理类型过滤 |
| `auto_bind` | bool | false | 获取后自动创建绑定 |

**响应：**

```json
{
  "added": 100,
  "message": "Fetched 100 proxies from server",
  "bound": 100
}
```

#### 绑定管理（/bindings）

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET /bindings` | 列出所有活跃绑定 |
| `POST /bindings` | 创建单个绑定 |
| `POST /bindings/batch` | 批量创建绑定 |
| `DELETE /bindings/{tag}` | 删除单个绑定 |
| `DELETE /bindings/all` | 删除所有绑定 |

**从 store 创建绑定（自动分配端口）：**

```bash
curl -X POST http://127.0.0.1:9090/bindings \
  -H "Authorization: Bearer your-secret" \
  -d '{"proxy_id": "stored-proxy-uuid"}'
```

**手动指定 outbound 和端口：**

```bash
curl -X POST http://127.0.0.1:9090/bindings \
  -H "Authorization: Bearer your-secret" \
  -d '{
    "tag": "my-proxy",
    "listen_port": 8888,
    "outbound": {"type": "vmess", "..."}
  }'
```

**批量创建绑定：**

```bash
# 绑定所有存储的代理
curl -X POST http://127.0.0.1:9090/bindings/batch \
  -H "Authorization: Bearer your-secret" \
  -d '{"all": true}'

# 绑定前 100 个 vmess 代理
curl -X POST http://127.0.0.1:9090/bindings/batch \
  -H "Authorization: Bearer your-secret" \
  -d '{
    "count": 100,
    "filter": {"type": "vmess"}
  }'

# 绑定指定代理
curl -X POST http://127.0.0.1:9090/bindings/batch \
  -H "Authorization: Bearer your-secret" \
  -d '{"proxy_ids": ["id1", "id2", "id3"]}'
```

**批量绑定响应：**

```json
{
  "created": 100,
  "failed": 2,
  "bindings": [
    {"proxy_id": "id1", "local_port": 20001},
    {"proxy_id": "id2", "local_port": 20002},
    ...
  ]
}
```

**批量过滤参数：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `proxy_ids` | string[] | 指定代理 ID 列表 |
| `all` | bool | 绑定所有代理 |
| `count` | int | 绑定前 N 个代理 |
| `filter.type` | string | 按代理类型过滤（vmess/vless/trojan 等） |
| `filter.source` | string | 按来源过滤（server/manual/subscription） |

**删除所有绑定：**

```bash
curl -X DELETE http://127.0.0.1:9090/bindings/all \
  -H "Authorization: Bearer your-secret"
```

### 典型使用流程

#### 场景：批量注册需要 100 个不同 IP

```bash
# 1. 从 Proxy Server 获取 100 个代理
curl -X POST http://127.0.0.1:9090/fetch \
  -H "Authorization: Bearer secret" \
  -d '{"server": "https://proxy.mui.moe", "api_key": "your-key", "count": 100}'

# 2. 批量创建绑定 → 每个代理分配一个本地端口
curl -X POST http://127.0.0.1:9090/bindings/batch \
  -H "Authorization: Bearer secret" \
  -d '{"all": true}'

# 3. 查看绑定列表，获取端口映射
curl http://127.0.0.1:9090/bindings -H "Authorization: Bearer secret"

# 4. 并发使用不同端口 → 不同出口 IP
curl -x http://127.0.0.1:20001 https://httpbin.org/ip  # → IP-A
curl -x http://127.0.0.1:20002 https://httpbin.org/ip  # → IP-B
curl -x http://127.0.0.1:20003 https://httpbin.org/ip  # → IP-C
...
```

#### 场景：使用订阅 URL

```bash
# 1. 添加订阅
curl -X POST http://127.0.0.1:9090/subscriptions \
  -H "Authorization: Bearer secret" \
  -d '{"name": "airport", "url": "https://airport.example.com/sub"}'

# 2. 批量绑定订阅中的代理
curl -X POST http://127.0.0.1:9090/bindings/batch \
  -H "Authorization: Bearer secret" \
  -d '{"all": true, "filter": {"source": "subscription"}}'

# 3. 后续刷新订阅（更新代理列表）
curl -X POST http://127.0.0.1:9090/subscriptions/{sub-id}/refresh \
  -H "Authorization: Bearer secret"
```

#### 场景：一步到位（fetch + 自动绑定）

```bash
curl -X POST http://127.0.0.1:9090/fetch \
  -H "Authorization: Bearer secret" \
  -d '{
    "server": "https://proxy.mui.moe",
    "api_key": "your-key",
    "count": 200,
    "country": "US",
    "auto_bind": true
  }'
# 响应: {"added": 200, "bound": 200, "message": "..."}
# 此时 127.0.0.1:20001~20200 已经全部可用
```

### 客户端编译

```bash
cd sing-box-zenproxy
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o sing-box -tags with_clash_api ./cmd/sing-box
```

### 客户端配置

sing-box 最小配置（`config.json`）：

```json
{
  "log": {"level": "info"},
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "your-secret"
    }
  },
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ]
}
```

启动后 Clash API 监听 `127.0.0.1:9090`，所有代理通过 API 动态管理。

### 客户端目录结构

```
./
├── sing-box           # 修改版 sing-box 二进制
├── config.json        # sing-box 配置
└── data/
    └── store.json     # 代理存储（自动生成，持久化）
```

### 数据持久化

代理和订阅数据存储在 `data/store.json`，重启 sing-box 后自动加载。绑定（inbound/outbound 端口映射）不持久化，重启后需要重新调用 `/bindings/batch` 创建。

---

## 三、修改版 sing-box 说明

Proxy 使用的 sing-box 在官方版本基础上新增了 **动态绑定管理**，支持运行时通过 REST API 增删代理绑定，无需重启进程。

### 原有 Bindings API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET /bindings` | 列出所有绑定 |
| `POST /bindings` | 创建绑定 |
| `DELETE /bindings/{tag}` | 删除绑定 |

### 新增能力（本次改造）

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST /bindings` | 增加 `proxy_id` 字段，从 store 获取 outbound 并自动分配端口 |
| `POST /bindings/batch` | 批量创建绑定 |
| `DELETE /bindings/all` | 删除所有绑定 |
| `GET /store` | 列出存储的代理 |
| `POST /store` | 添加代理（URI 或 outbound JSON） |
| `DELETE /store/{id}` | 删除代理 |
| `DELETE /store` | 清空所有代理 |
| `GET /subscriptions` | 列出订阅 |
| `POST /subscriptions` | 添加订阅 |
| `DELETE /subscriptions/{id}` | 删除订阅 |
| `POST /subscriptions/{id}/refresh` | 刷新订阅 |
| `POST /fetch` | 从 Proxy Server 获取代理 |

## 日志

### 服务端

```bash
RUST_LOG=zenproxy=info,tower_http=info ./zenproxy
RUST_LOG=zenproxy=debug ./zenproxy  # 调试模式
```

### 客户端

在 `config.json` 中设置 `log.level`：`debug` / `info` / `warn` / `error`。
