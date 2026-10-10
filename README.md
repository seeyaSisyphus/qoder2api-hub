# Qoder2API-Hub — 国际版、国内版多账号网关中枢

<p align="center">
  <img src="https://img.shields.io/badge/Release-v1.0.0-2496ED?style=flat-square" alt="Version 1.0.0">
  <img src="https://img.shields.io/badge/Python-3.9+-blue.svg?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/API-OpenAI_Compatible-412991?style=flat-square" alt="OpenAI API">
  <img src="https://img.shields.io/badge/Dual_Realm-CN_&_Intl-0DBD8B?style=flat-square" alt="Dual Realm">
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Zero-Dependency-ff69b4?style=flat-square" alt="Zero Dependency">
</p>

本项目为 **Qoder2API-Hub**，将阿里 **[qoder.com.cn](https://qoder.com.cn)** (国内版) 与 **[qoder.com](https://qoder.com)** (国际版) 的原生服务封装为标准 OpenAI 兼容接口，支持 Chat Completions 与 Responses API。具备多账号负载轮询、稳定物理设备指纹隔离、OAuth 设备授权一键免客户端登录、每日签到与实时额度查询、Pro 福利包自动领取、后台常驻定时调度器、Web 监控看板等全套能力 —— 与 WorkBuddy2API-Hub 同构的完整功能矩阵。

- **开箱即用**：双击批处理脚本即启；亦支持 Docker 容器化部署，零外部 pip 依赖。
- **本机已登录凭证一键入池（双区）**：只读探测桌面 App（`auth.v1.dat`，os_crypt/DPAPI 解密）与 Qoder CLI（`~/.qoder*/.auth/user`，AES-128-CBC）两类官方存储，看板两步确认导入，永不静默采用。
- **模型清单完全跟官方走（双区不同、以官方此刻为准）**：三源优先级 —— 动态 `/algo/api/v2/model/list`（COSY 签名，**GET 需携带与签名一致的 `{}` body，否则 403**）> 本机官方客户端模型目录缓存（`~/.qoder*/.models/<uid>/catalog-v6`，QMC/HKDF+AES-256-GCM 解密）> 内嵌双区官方快照；清单**以动态源返回的集合为准**（官方桌面版此刻显示什么这里就显示什么，如国际版动态 15 条就不多塞静态独有的 `smodel/cmodel`）。**逐字段忠实保留**：`id` = **官方模型名**（如 `Qwen3.8-Max`，客户端唯一需要填的值；`upstream_key`/`aliases` 同时给出 key、`key (Name)` 与人类别名等全部可填形式）、官方桌面版介绍文案（`description`，取自客户端 dynamic-text）、本地化名（`name_local`，如 Ultimate→极致）、`context_config` 多窗口（200K 默认/400K/1M）、`thinking_config` 思考档位（low/medium/high/xhigh/max + 默认标注 + 可关闭）、**峰谷价**（`price_factor_peak` 促销前倍率 → `price_factor_valley` 谷时倍率 + `off_peak` 时段窗口 22:00-08:00 与官方错峰文案）、`is_free/is_new`；官方 `enable=false` 条目不过滤，附**官方原文禁用原因**（`disabled_reason = "需要升级或购买千问官方套餐开放"`，并透传上游 `disabled_message_key`）。**最大输出**：官方 catalog 与动态接口原始响应均无此字段，故不再输出/展示任何编造值。
- **双区域独立路由**：支持 🌐 国际版 (qoder.com / api3.qoder.sh) 与 🇨🇳 国内版 (qoder.com.cn / gateway.qoder.com.cn) 独立配置与管理，区域独占模型（如国内 `q37fmodel`/`glm-5.2`、国际 `smodel`/`ultimate`）自动路由到归属出口并拦截错配 Key，看板一键切换且状态落盘持久化。
- **COSY 签名推理链路**：RSA 包裹 AES 会话密钥 + MD5 请求签名 + 自定义 Base64 请求体编码，纯标准库实现（含 AES-128/256、RSA-PKCS1v15、GCM、DPAPI、QMC 纯 Python 实现，Docker alpine 下同样零依赖），逆向对齐官方桌面/CLI 客户端协议。
- **稳定物理设备指纹隔离 (`derive_id`)**：以账号自身 UID 稳定哈希派生专属 `cosy-machineid` / `cosy-machinetoken` / 会话标识，同一账号长期固定在同一台虚拟物理设备，天然防多号关联风控。
- **OAuth 设备授权一键免客户端登录**：PKCE (S256) 设备流（双区 URL 参数按官方差异构造：国内带 `redirect_uri+client_id+machine_id`，国际带 `client_id+machine_id`），点击看板链接在浏览器完成授权即可自动入池；亦支持 PAT (`pt-`) 导入，jobToken 自动交换与轮换。
- **每日签到与额度体系（官方能力门控）**：签到/Pro 福利活动**仅国内版提供**（国际版官方无签到接口）；国内版每日签到（活动 `DISABLED` 时诚实跳过不硬领）、连续签到统计、Pro 升级包资格检查与领取、quota/usage 额度与套餐快照实时刷新。
- **后台常驻定时调度器**：每日 22:00 Token 集中保活（签到已移交 `qoder2api` 计划任务，见 §4），`drt-` / `jrt-` 按前缀路由刷新，PAT 最终兜底。
- **双协议全功能支持**：同时支持标准 OpenAI Chat Completions 协议与 Responses API (Codex / Claude Code)，含 custom freeform 工具（`apply_patch`）双向转译、DSML 工具调用回退解析与内部协议文本的泄漏回读；上游被切断的 SSE 帧自动重组。
- **现代化 Web 看板**：弹性指标卡片、签到与福利中心、模型能力清单、性能指标与用量透视、实时请求流水与运行日志。

> ⚡ 本项目架构与交互对齐 WorkBuddy2API-Hub，上游协议替换为 Qoder COSY 签名体系。

---

## 🖼️ 看板预览 (Dashboard Preview)

**网关总览** —— 双区出口状态、调度器、账号池与请求流水一屏尽览：

![网关总览](docs/img/dashboard.png)

**模型清单** —— 与官方桌面版同源：官方模型名、峰谷价、上下文多窗口、思考档位、能力徽标：

![模型清单](docs/img/models.png)

**数据指标看板** —— Token 消耗透视、TTFT 首字延迟、生成速度与缓存命中率：

![数据指标看板](docs/img/metrics.png)

**签到与福利中心** —— 每日签到领积分、Pro 福利包一键领取（仅国内版）：

![签到与福利中心](docs/img/benefits.png)

---

## 一、快速启动

### 1. 本机单机使用
双击运行 **`start-qoder-proxy.bat`**，保持窗口运行：
- **API 接口地址**：`http://127.0.0.1:8790/v1`
- **Web 监控看板**：`http://127.0.0.1:8790/`

> ℹ️ 默认端口 **8790**（8788 被 `mimo-api-proxy.mjs` 占用，8789 为 wb-proxy 默认）。改端口：`start-qoder-proxy.bat 8791`。

首次启动若无账号，直接打开看板点击 **「+ 添加账号 (OAuth)」**，在浏览器完成设备授权即可自动加入；或点 **「🔑 导入 PAT」** 粘贴个人访问令牌。

### 2. 面板访问密码

打开看板需要先输入**面板访问密码**，默认是 `admin`。它与 API Key 相互独立：

- 面板密码只用于打开网页看板，可在看板「设置」页修改（也可启动时 `--panel-password` 指定）；
- 密码以 PBKDF2-SHA256 摘要形式保存在 `accounts/settings.json`，不存明文；
- 登录状态存放在浏览器会话中，关闭浏览器或重启网关后需要重新输入。

> 首次登录后请立即到「设置」修改默认密码。

### 3. 局域网共享模式
双击运行 **`start-qoder-proxy-lan.bat`**，允许局域网内其他设备访问：
- **Base URL**：`http://<本机局域网IP>:8790/v1`
- **密钥随机生成并持久化**：LAN 模式首次启动生成高强度随机 API Key（`qd-` 前缀），保存到 `accounts/settings.json` 并在终端打印，重启复用。
- **自定义 Key**：`start-qoder-proxy-lan.bat 8790 我的Key`
- 支持带密钥直达面板：`http://<IP>:8790/?key=生成的Key`。
- 其他设备连不上时，管理员运行一次 `allow-firewall.bat` 放行防火墙。

### 4. 多 API Key 管理与出口绑定

网关支持**多 API Key 并行管理**，并可为每个 Key 指定独立出口：

- **添加与在线生成**：看板「设置」页，输入名称 + 一键生成随机 Key；
- **出口自由绑定**：
  - 🌐 **国际版出口**：该 Key 流量强制走 `api3.qoder.sh`
  - 🇨🇳 **国内版出口**：该 Key 流量强制走 `gateway.qoder.com.cn`
  - **跟随面板切换**：未绑定出口的 Key 实时跟随看板顶部全局出口
- **状态管理**：单独启停、一键删除，删除即刻失效；配置持久化到 `accounts/settings.json`；
- **安全防冲突**：面板配置过 Key 后，启动脚本里的旧 `--api-key` 自动失效；
- **模型区域自检**：Key 出口与模型区域不匹配时返回通俗 400，杜绝上游晦涩拒流报错。

### 5. 网络出口与 TLS 指纹（风控特征收敛）

本网关对**出站网络特征**做了显式收敛，避免多账号反代中最容易被关联的两类信号：

#### 出口（egress）：默认直连，忽略进程级代理变量

Python 的 `urllib` 默认 opener 会隐式读取进程级 `HTTP_PROXY` / `HTTPS_PROXY` /
`ALL_PROXY`。网关进程一旦继承用户级代理变量，**连国内版（qoder.com.cn）也会被迫走代理**，
把两个本来独立的故障域耦合在一起（代理一抖，全线瘫痪）。因此：

- **默认直连**，不读上述环境变量；
- 需要代理时显式配置：全局用 `QD_HTTP_PROXY` / `QD_HTTPS_PROXY`；
- **账号级出口**：账号 JSON 加 `"egress": {"https_proxy": "http://127.0.0.1:7890"}`，
  实现「一账号一出口」（原则：一个账号长期一个出口，不随请求轮换 IP）；
- **国内版（`*.qoder.com.cn`）与 localhost 始终直连**——这是来自真实事故的结论：
  多账号共用境外机房 IP 时 WAF 高频拦截，切回大陆家宽直连后 WAF 归零且快 4.6 倍；
  强制直连也避免代理抖动把两个独立故障域耦合起来；
- **国际版（`*.qoder.sh`）可走显式配置的代理**（未配置时同样直连），
  便于按区分离出口；
- `GET /health` 的 `egress` 字段显示当前模式（`direct` / `proxy(configured)`）。

> ⚠️ 升级注意：若你原先依赖 `HTTP_PROXY` 访问国际版，需改用 `QD_HTTPS_PROXY`，
> 否则会静默变直连。升级后先看 `/health` 的 `egress` 字段确认。

#### TLS 指纹（可选，默认关闭）

**这是 HTTP 头无法掩盖的一层。** Python 标准库的 TLS `ClientHello` 是 OpenSSL 出厂形态
（无 GREASE、无 ALPN、11 个扩展），JA3 恒为 `93c7d42c0df602fb91589311534831f5` ——
全世界所有 Python 脚本共用同一指纹。由于它在 TLS 握手层、位于 HTTP 之下，
无论 `User-Agent` 声称什么，都无法改变它。

如需收敛这一层，可**可选**启用 curl_cffi 模仿真实客户端握手：

```bash
pip install curl_cffi
export QD_TLS_IMPERSONATE=chrome    # 或 chrome131 / edge101 / safari17_0 等
python qoder_proxy.py --port 8790
```

- 启用后一次性解决 **JA3 + ALPN + HTTP/2 + 头顺序**；
- 自定义头（`User-Agent`、`cosy-*` 等）**不受影响**，仍按账号/区域正常发送；
- **未安装 curl_cffi 时自动回落标准库**并打印一次告警，不影响可用性；
- `GET /health` 的 `tls` 字段显示当前模式（`stdlib-openssl` / `impersonate(chrome)`）。

> 保持**默认关闭**是为了守住「纯标准库、零依赖」这条约束（见 Docker alpine 构建）。
> 自用低频网关通常不必开启；若上游做 TLS 指纹评分，这是唯一有效的应对手段。

### 6. 可观测性与日志（溯源排查）

一次请求的**全链路**可在事后重建，无需复现：

- **`req_id`**：每个推理请求一个 12 位 ID，贯穿该请求的**所有**日志行与落盘记录。
  并发时能把散落的日志按 ID 串成一条链（`log()` 自动加 `[req_id]` 前缀）。
- **`usage/events.jsonl`**：机器可读的结构化事件流 —— `request.start` /
  `queue.wait`（排队每轮一条）/ `retry`（含原因与退避）/ `client.gone` /
  `request.end`（含全部遥测）。
- **`usage/usage.jsonl`**：每请求一行，含 `req_id`、`queue_waits`、`queue_ms`、
  `queue_max_hint_s`、`attempts`、`account_switches`、`retry_reasons`。
- **`usage/server.log`**：文本日志（stderr 的落盘副本，VBS/服务方式启动时也能查）。

**排查示例**（排队多久、能不能等到）：

```bash
# 排队统计：排过队的请求有多少、等多久、成功率
curl -s localhost:8790/usage | python -c "import sys,json;print(json.load(sys.stdin)['queue'])"

# 某次请求的完整链路（先用 req_id 从 usage.jsonl 找到它）
curl -s 'localhost:8790/logs?req=<req_id>'
```

**轮转**：`usage.jsonl` / `events.jsonl` / `credits.jsonl` / `server.log` 均按大小
轮转（默认 8MB × 5 份，`QD_LOG_ROTATE_MB` / `QD_LOG_ROTATE_KEEP` 可调）—— 排队预算
是 15 分钟量级，无轮转会无界增长。

#### 积分消耗统计（`usage/credits.jsonl`）

**上游不逐请求报积分**：每个响应的 `usage.credit` 字段恒为 0，也没有按天用量接口
（`/quota/usage/daily` 等候选端点全部 404）。账号额度接口只给**累计值**
（`userQuota`/`addOnQuota` 的 `used`/`remaining`/`total`）。

因此「某时段消耗了多少积分」无法从任何单一来源算出，只能靠**快照差值**还原：

- 把每个账号的额度快照追加进 `usage/credits.jsonl`（一行一个时间点，含
  `totals` 汇总与 `accounts` 逐账号明细）。
- **采样时机：每天定点一次**（默认 **08:00**，`QD_CREDITS_SNAPSHOT_AT` 改，
  设空串关闭），外加**启动补采**（当日尚无快照时）与**面板「刷新积分」**。
- **当日消耗 = 相邻采样点的 `used` 差值**，即「昨日 08:00 → 今日 08:00」这一
  天的用量。同时给出 `remain` 减量作互证 —— 两者不等说明期间有签到/福利补额。

```bash
# 最近 14 天的每日积分消耗（合计 + 逐账号）
curl -s -H "Authorization: Bearer <key>"   'localhost:8790/usage/credits?days=14' | python -m json.tool

# 直接看原始快照（每行一个时间点）
tail -3 usage/credits.jsonl
```

> 每天 08:00 采一条：**当天 08:00 之后**的用量会算进**次日**那一行（因为要用
> 次日 08:00 的快照减今天 08:00 的）。首个采样点没有前驱，标 `pending`。

### 7. Docker 容器化部署

```bash
# 1. 后台启动容器 (自动构建并运行)
docker compose up -d

# 2. 查看网关日志
docker compose logs -f
```

或直接 `docker run`：

```bash
docker run -d --name qoder-proxy --restart unless-stopped \
  -p 8790:8790 -v $(pwd)/accounts:/app/accounts -v $(pwd)/usage:/app/usage \
  -e API_KEY=your_secret_key $(docker build -q .)
```

- **持久化目录**：`./accounts`（账号凭证及出口设置）与 `./usage`（请求流水与指标快照）；
- **配置参数**：环境变量 `API_KEY`、`PORT`。

---

## 二、核心特性详解

### 1. 请求链路（COSY 签名推理）

**瞬时故障韧性（双层）**：上游把自己的 provider 故障包装成 `418/5xx + provider_error` 抛回，或对 `qoder.sh` 出现 TLS/连接抖动（`SSL: UNEXPECTED_EOF...`）时：
- **连接层**（urlopen 时刻的 HTTP/传输错误）：同账号快速重试 2 次（1s/2s 退避）；
- **流内信封层**（关键形态：上游先 HTTP200 建流、再在 SSE 信封里投 `statusCodeValue=418`——表现为 access log 记 200 而业务错 418）：在**尚未向客户端写出任何上游字节**前重开上游重试 2 次（chat 流式/非流式 + Responses 全覆盖），流式客户端全程无感。

重试仍失败才**短冷却（15s，单账号池实际 3s）换号**——不因上游的锅罚账号 60 秒；**短错误冷却期间（≤10s）后续请求改为「等待续上」而非报错**，且 `429 usage exceeds frequency limit` **只在上游真频控时出现**（账号错误冷却不再被误标为频控）。客户端参数错误（`invalid_parameter_error` 等）与**上游内容安全审核拒绝**（`InternalError.Algo.DataInspectionFailed: Input text data may contain inappropriate content`）**绝不重试**、快速失败——后者返回中文解释（`content_policy_rejected`：确定性拒绝、重试无效，请检查/缩短输入），由调用方修改输入而非等待。耗尽后其余瞬时错误客户端收到中文友好提示（`upstream_transient_error`）；错误详情经 `qoder_detail` 挂载保留 400 字节完整送达日志（含内层 `details`）。

**账号额度耗尽（110/112）与排队是两件相反的事：排队要等，额度耗尽要换号**

| 上游码 | 含义 | 处置 |
|---|---|---|
| `10605` | 模型级容量门控（排队） | **等**上游放行（预算 15 分钟） |
| `110` | `Billing daily count exceeded`（账号当日额度用尽） | **换号** + 该号跨日排除 |
| `112` | 需订阅 / 额度不足（附 `pricingUrl`） | **换号** + 该号跨日排除 |

曾把 110/112 当普通 403 早退，**不换号、直接失败** —— 实测池中 7 个额度充足的
账号被闲置，整个请求报废（2026-10-02 15:54，客户端表现为反复 `Reconnecting`）。
现在：

- 三条链路（非流式 / chat 流式 / responses 流式）**都先判额度、再判瞬时性**；
- 撞上 110/112 的账号打 **`quotaUntil` 跨日排除**（取「下一个本地 00:00」与固定兜底
  的较晚者，`QD_QUOTA_COOLDOWN_S` 可调，默认 6h），下次选号自然跳过；
- 换号重开（额度是账号级状态，换号立刻有效；代价仅一次 prompt 缓存损失）；
- **全池额度耗尽**时返回 **429 + `Retry-After`**（而非无退避提示的 403，或会被误读成
  「池子坏了」的 503），文案为 `account_quota_exhausted` 并说明「等待次日重置或补充账号」。
- 看板可区分「被限流」（`inCooldown`）与「没额度」（`quotaExhausted`/`quotaFor`）——
  两者运维处置完全不同。
**上游排队（10605）不是凭证拒绝，也不是频控**：低优先级（p3）模型被容量门控时，
上游以 **HTTP200 建流 + SSE 信封 statusCodeValue=403（内嵌 10605 排队体）** 投递。
处理原则（每条都对应一次实测事故）：

1. **不冷却账号、不写 `model_cooldowns`**。排队曾被写进频控冷却，使
   `realm_model_throttled()` 判定「整池被上游频控」，之后**所有**请求（含其它模型）
   秒回 429 —— 一个瞬时排队信号打瘫整个池。现在排队与频控严格分开存储。
2. **不换号**。实测同池账号会**一起**排队（`queueCount` 常为 0 而
   `serviceAvailable=false`），换号拿不到服务；而在一个请求内轮换会把整池账号
   全标记成不可用，后续请求随即全部 429。故改为**等上游放行后原样重开**。
3. **等待期间放掉在途名额**。抱着并发额度睡 30s，会让本号在别的请求眼里变成
   `at capacity` 而被换号 —— 一个排队请求就能占满整号的并发额度。
4. **等待预算默认 900s（15 分钟）**，`QD_QUEUE_WAIT_BUDGET` 可调。一次请求的初开与
   所有重开**共用同一个截止时间**（否则每层各开一轮预算，总等待会叠加 —— 实测过
   80s+ 超过客户端超时）；单次等待夹到剩余预算内；轮数上限由预算推导（不写死，
   它同时是防止小 hint 下高频重试的限速阀）。
5. **等待期间探测客户端是否断开**（`MSG_PEEK` 非破坏性探测）：用户在客户端点「停止」
   或客户端自身超时后，网关**立刻放弃等待**、不再向上游重试。没有这道保险，大预算会
   留下长时间空转的请求，每 30s 打一次上游却没人接收 —— 正是要避免的流量特征。
   （实测：客户端 t=3s 断开后，12s 内只多打 1 次上游；无探测时同期会打满十余次。）
   
   > ⚠️ **预算仍应小于你客户端的超时**：否则客户端会在网关还在等的时候先断开，用户
   > 看到的是**超时**而不是结果（断开探测能止损，但那次等待本身白费了）。默认 900s
   > 适合超时宽松、且自带「排队中」提示的客户端；客户端超时较短的部署请调小，例如
   > `QD_QUEUE_WAIT_BUDGET=40`。
5. 预算耗尽才以 **429 + Retry-After**（取上游 retryAfterSeconds）交还客户端重试，
   且**不惩罚账号**——排队期间账号始终是健康的。

**账号池选号（均匀分布）**：新会话按「**日请求数 / 在途数最小者优先**，同负载按游标轮询打破平局」选号——负载相同时退化为纯轮询，负载偏斜时自动补给落后账号，各账号请求量长期趋近相等；单号并发（默认 2）与日总量（默认 1200）上限由 try_acquire 统一把关，满员自动跳过换号；已有会话保留**前缀亲和**（同一对话固定账号，护住上游 prompt 缓存），仅当该号不可用、日量耗尽或排队冷却时才改选。

```
客户端 OpenAI 请求
  → build_qoder_body()   官方 baseprompt 模板 + 会话压平（system/工具/参数覆写）
  → qoder_encode()       Qoder 自定义 Base64（标准 B64 三段轮转 + 字母表映射, '=' → '$'）
  → COSY 签名            RSA(1024) 包裹 AES-128 会话密钥 → info(AES-CBC 身份)
                         Bearer = COSY.{payloadB64}.{md5(payload\ncosyKey\ndate\nbody\npath)}
  → POST {gateway}/algo/api/v2/service/pro/sse/agent_chat_generation?…&Encode=1
  → SSE 帧重组           被切断/注入裸换行的帧按空行分块拼回（社区实测约 3% 事件）
  → SSE 信封解包          {"headers","body","statusCodeValue"} 嵌套帧 → 内层 OpenAI chunk
  → 标准 OpenAI SSE / chat.completion 回给客户端
```

模型清单按**三源优先级**完全对齐官方（详见「核心特性 · 模型清单」）：

```
1) 动态接口  GET {gateway}/algo/api/v2/model/list?Encode=1   （COSY 签名，需账号，300s 缓存）
2) 本机官方客户端目录 ~/.qoder*/.models/<uid>/catalog-v6      （QMC 解密，离线可用）
3) 内嵌双区官方快照 qoder_catalog.py                           （兜底）
```

**双区清单不同**（源自本机官方客户端 catalog 的**全字段**忠实快照，chat 场景；`id` = 官方模型名，直接照抄即可）：

- 🇨🇳 **国内版 (动态 14 条，全部开通)**：`Auto` · `Qwen3.8-Max` · `Qwen3.8-Flash` · `Qwen3.7-Max` · `Qwen3.7-Plus` · `Qwen3.7-Flash` · `DeepSeek-V4-Pro` (96K) · `DeepSeek-Flash` · `GLM-5.3` · `GLM-5.3-Flash` (1M) · `GLM-5.2` · `Kimi-K3` · `Kimi-K2.8-Preview` · `MiniMax-M2.7`
- 🌐 **国际版 (动态 15 条；开通 2、未开通 13)**：`Qwen3.8-Max`、`Qwen3.8-Flash` 开放；其余（`Ultimate`/`Performance`/`Efficient`/`DeepSeek-V4-Pro`/`MiniMax-M3`/`Auto` 等）标注**官方原文**「需要升级或购买千问官方套餐开放」+ 上游 `disabled_message_key`（`codeSafeModelReason`），**不隐藏条目**（与桌面版此刻同一份清单）。

**峰谷价（官方 `promotion` 字段）——低谷折扣模型共 3 个（双区一致），全部高亮**：

| 模型 | 峰价 | 谷价 | 折扣（官方 badge） |
|---|---|---|---|
| `Qwen3.8-Max` (`qmodel_38max`) | 0.50x | 0.20x | 错峰 4 折 |
| `Qwen3.7-Max` (`qmodel_latest`) | 0.50x | 0.10x | 错峰 2 折 |
| `Qwen3.7-Plus` (`qmodel`) | 0.10x | 动态为准（快照 0.04x） | 错峰 4 折 |

均为 22:00-08:00 窗口（`Qwen3.8-Flash` 另有限时免费 0.00x，原 `0.10x`）。`/v1/models` 与看板对**每个**促销模型输出 `price_factor_peak` / `price_factor_valley` / `off_peak{window_start,window_end,badge,description,discount_factor,timezone}` 与 **`off_peak_active_now`**（按官方时区 UTC+8 跨午夜窗口判定当前是否处于低谷）。判定顺序上 **promotion 分支优先于 0 价分支**——`is_free` 表示"含免费权益"而非 0 价（Qwen3.8-Max `is_free=true` 但价 0.20x），不会被错标成免费、也不会吞掉低谷高亮（单测有分支顺序回归断言）。

**低谷时段视觉高亮**：看板在低谷窗口（22:00-08:00）内把价签切换为**亮绿发光高亮块**——大号谷价 +「● 低谷生效中」徽标 + 峰价红色删除线 + 时段/折扣文案；非低谷时段显示常规「峰 x → 谷 x」并提示「低谷自 22:00 起」。判定用后端字段 + 浏览器本地时间即时复算双保险，跨窗口自动切换。

同 key 跨区也可能不同（`mmodel` 国际=MiniMax-M3、国内=MiniMax-M2.7）；上下文窗口、倍率、视觉/推理标志逐项取自官方条目（如国内 `dmodel` 96000、国际 `dmodel` 1000000）。

**上下文窗口：默认值 ≠ 上限。** `context_config` 给出该模型的全部档位（通常
200K / 400K / 1M，其中一档标 `is_default`）。此前把 `max_input_tokens`（GLM-5.3、
Kimi-K3 等为 180000）当上限直接硬写，导致客户端显示「只有 180K」—— 而官方 App
对同一模型提供 200K/400K/1M 滑块，历史流量里 GLM-5.3 也实际吃过 **466K** 输入。
现在的口径：

- `context_length` = **最大可选窗口**（滑块右端，即「能调到多大」）；
- `context_window_default` = 官方默认档位（数值，token 数）；
- 发给上游的 `model_config.max_input_tokens` = 官方默认档位，**可被客户端按请求
  覆盖**：传 `context_window`（或 `max_input_tokens`）字段即可，值会**夹到该模型
  的合法档位**（如 999999 → 400K）。两个字段都会被剔除、不污染转发体。

```bash
# 让本次请求按 1M 窗口发（GLM-5.3 支持 200K/400K/1M）
curl -s localhost:8790/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"GLM-5.3","context_window":1000000,"messages":[{"role":"user","content":"hi"}]}'
```请求侧接受 key / 展示 id「key (Name)」/ 人类可读别名 / 官方显示名任意形式；区域独占模型（国内 `q37fmodel`/`glm-5.2`、国际 `smodel`/`ultimate` 等）自动路由到归属出口。

### 2. 拒绝与异常结束的规范化（`finish_reason`）

上游会返回**规范外**的 `finish_reason`。实测见到 `refusal`（模型主动拒绝——
其 system prompt 含安全条款，例如「Refuse to create, modify, or improve code
that may be used maliciously」）。规范外值若原样透传，客户端无法归类，表现为
异常状态提示。

处置（三条不变式，均有回归测试）：

1. **归一化**：规范外值映射到语义最近的标准值（`refusal` → `content_filter`，
   未知值 → `stop`），并写一条 `finish_reason.mapped` 事件保留「原始值 → 归一值」，
   使归一不丢信息。合法值原样通过。
2. **请求必闭合**：拒绝类响应往往**不带 `usage`**，而 `record_usage` 原先在无
   usage 时提前返回 —— 导致该请求在 `usage.jsonl` 与 `events.jsonl` 里**完全
   不存在**，事后无法定位。现在无论有无 usage 都落一行并发出 `request.end`。
3. **保留拒绝原因**：非流式响应的 `message.refusal` 与落盘行的 `refusal` 字段
   都保留原文，客户端/排查者能知道「为何被拒」，而不是只看到空内容 + 异常状态。

> 这是**模型自身的对齐行为**，网关无法阻止（客户端提供的 system prompt 会替换
> 上游模板基座，替换后仍可能被拒）。网关能做的是：让拒绝**可归类、可追溯**。
### 3. 孤儿 tool_calls 清理（否则工具调用会「持续失败」）

上游对**配对不完整**的 tool_calls 直接返 400：

```
The provided messages input is invalid.
The error info is [Can only get item pairs from a mapping.]
```

即 assistant 声明调用了某个 `tool_call` id，但缺少对应的 `role=tool` 结果 ——
客户端截断历史、子代理被取消、工具执行中断都会造成。**单条孤儿会让整次请求
失败**，而客户端每轮都带完整历史，于是该会话之后**每一轮都 400**，表现为
「工具调用持续失败」而非偶发。

处置（`cleanup_orphan_tool_calls`，在 `flatten_messages` 入口执行）：

| 情形 | 处理 |
|---|---|
| 双侧齐全（有调用、有结果） | 原样保留 |
| assistant 的 tool_calls 中**任一 id 未配对** | **整个 `tool_calls` 键删除**（保留 content） |
| `role=tool` 结果**无对应调用** | **整条消息删除** |
| 无工具消息的普通对话 | 零改动（不误伤） |

触发清理时记一条 WARN 日志（含 req_id），便于事后统计发生频率。

> 与 workbuddy 网关的 `cleanupOrphanToolCalls`（`internal/upstream/tool_pairing.go`）
> 同语义 —— 该保护是两者行为差异的来源之一。
### 4. 截断工具调用的清理（客户端报 `Unterminated string`）

SSE 流被截断时（连接中断 / `finish_reason==length` / 上游超时），工具调用的
`arguments` 会只剩**半截 JSON**。原样交给客户端会解析失败并卡死会话：

```
Validation failed for tool "edit": Tool call arguments are not valid JSON.
Parse Error: Unterminated string
```

处置（`is_truncated_arguments` + `drop_truncated_tool_calls`，与 workbuddy 网关
`internal/upstream/truncation.go` 同语义）：

| arguments | 判定 | 理由 |
|---|---|---|
| 空串 / 纯空白 | **不是**截断 | 合法的无参工具 |
| 非空但 JSON 解析失败 | **截断** | 分片丢失，残缺 |
| 能解析（含 `null`/标量/数组） | **不是**截断 | 合法 JSON |

**覆盖全部四条链路**（判定只看「参数能否解析」，不依赖 `finish_reason` 取值 ——
连接中断/上游超时不会产生 finish_reason 帧，只看 `length` 会全部漏网）：

| 链路 | 处置 |
|---|---|
| **chat 流式**（omp 主用，生产 590/673 次） | `iter_client_sse` 转发层：tool_calls 分片**按 index 缓冲**，收尾时逐 index 判定完整性 —— 可解析则按原顺序补发，残缺则整组丢弃；有丢弃时收尾帧一律降级 `length`（`stop`/`tool_calls` 皆然）。content/reasoning 仍即时透传，另含 DSML 文本兜底（见 §4.1）。 |
| chat 非流式聚合 | 丢弃残缺调用（WARN 日志）；**只要**有调用被丢弃，`finish_reason` 一律置 `length`（哪怕还有合法调用、哪怕全丢光）—— 客户端据此重试/续写，而不是把残缺轮次当「成功的空响应」 |
| responses 流式 | arguments 分片**不在聚合期下发**（半截 JSON 一旦写出就无法撤回），收尾判定完整才补发 `function_call_arguments.delta`；残缺则补发 `output_item.done`（`status: incomplete`）维持 added/done 配对，**不带 `arguments` 字段**（空串会被客户端解析成 `{}` 并执行）；整轮置 `incomplete` |
| responses 非流式 | 丢弃残缺调用；整轮 `status: incomplete`（`incomplete_details.reason=max_output_tokens`） |

> **custom freeform 工具例外**：这类工具的载荷本就是自由文本（网关的
> `CUSTOM_TOOL_HINT` 要求模型原样放入 `input`），不是 JSON，按「能否解析」
> 判会误杀 —— 四条链路都对该类工具跳过截断判定。
>
> **控制流异常不得触发补发**：`UpstreamStatus`（排队/额度/瞬时信封）与
> `GeneratorExit` 直接放行，否则先下发的缓冲帧会把 handler 的 `emitted`
> 置真，导致 in-stream 排队等待与瞬时重开被静默关闭。
>
> **为什么流式必须缓冲**：SSE 分片一旦写出就无法撤回，而 arguments 是否完整
> 只有到收尾才能判定。直接透传时半截 JSON 进入客户端累积 buffer，客户端在流
> 结束时严格解析失败。缓冲仅影响 tool_calls 分片的**到达时间**（推迟到收尾），
> 内容与直接透传等价；文本/思考帧不受影响，流式体验不变。

> 残缺调用**丢弃**而非补成 `{}`：后者会伪造「合法」外观，让客户端误以为
> 工具调用成功，掩盖了流被截断这一事实。
### 4.1 工具语境隔离与 DSML 文本兜底

**工具语境隔离**（`build_qoder_body`）：客户端自带 tools 但**没带 system** 时，不再
继承 `baseprompt.json` 里那 12KB 的 Qoder CLI 系统提示词 —— 它教的是 Qoder 桌面端
内置工具（Task/TodoWrite/Edit/Bash…）的用法与桌面端语境（如
`Working directory: D:/Projects/Qoder`），模型会照着写出与客户端实际声明的工具
schema 不符的调用（实测表现为非法工具 payload、半截/错位 arguments）。此时改用中性
基座（`SYSTEM_PROMPT`，默认 `You are a helpful assistant.`），工具定义完全以客户端
`tools` 为准。客户端自带 system 时仍以客户端的为准；既无 system 也无 tools 时保持
原行为（保留模板提示）。

**DSML 文本兜底**（chat 与 responses 双路径）：模型偶尔把调用写成 DeepSeek 风格的
`<｜DSML｜calls>…</｜DSML｜calls>` 文本而不是结构化 tool_calls。两条路径都在「本轮
没有任何结构化 tool_calls」时解析该文本并转成标准 tool_calls：

- **非流式**：组装完 message 后解析；命中则填 `message.tool_calls` +
  `finish_reason=tool_calls`，content 换成清理后的文本；
- **流式**：content 在起始候选之前即时透传，候选之后暂存；收尾（finish 帧 / 流结束）
  统一判定 —— 命中则补发 tool_calls 分片帧（首帧 id+name，次帧完整 arguments）并把
  收尾帧改写为 `tool_calls`；未命中则把暂存文本作为普通 content 补发。增量匹配器只做
  「与 `<｜DSML｜calls` 前缀相容」判定，普通文本里的 `<` 最多延迟一个片段；断流时
  暂存文本同样补发，不闷内容；
- **白名单**：仅当解析出的 invoke 名**全部**在客户端声明的工具名集合内
  （`declared_tool_names`）才转换，否则原样保留文本 —— 绝不把模型随手写的文本变成
  客户端不认识的工具调用。
### 4.2 内部协议文本的泄漏回读（上游 issue #8/#9/#11/#16 同源修复）

长会话里模型偶尔**照格式复述**网关内部协议文本而不是给结构化 tool_calls，客户端会
把这段文本当正文显示、本轮调用不执行。两条形态各自处置：

| 形态 | 判据 | 处置 |
|---|---|---|
| `[assistant 请求调用工具]` + JSON 数组 `[{name, arguments}]` | 整段 strip 后**恰好**是该形态（可带 ``` 围栏），数组非空、name 非空、arguments 是合法 JSON，且**所有 name 命中本次声明的工具名** | 还原为结构化 tool_calls（chat 流式为 tool_calls 增量帧 + 收尾帧改写 `tool_calls`；非流式为 `message.tool_calls`），正文清空 |
| `[工具结果…]` 回声块 | strip 后是合法开标记行，且出现闭标记 `[工具结果结束]` 或标记后以 `{["<` 开头 | **吞掉**（不还原：还原需要与历史 `tool_call_id` 配对） |

**截断防护**（issue #9/#16）：正文以 marker 开头、声明了工具、但数组**没写完/非法**
（含截断落在未写完的 `\uXXXX` 转义里）时整段吞掉 —— 绝不把内部协议文本透传给终端
用户。完整但未命中白名单的数组保持 fail-open 透传（那是模型在讨论该标记，不是回声）。

**流式 hold-back**（issue #16-B1）：跨帧补全窗口 = 最长标记长度 − 1（17 字符），
只有帧/缓冲**末尾**的这 17 字符内匹配到标记真前缀时才暂留；下一帧证伪立即补发
（fail-open）。「散文 + marker 落在同一帧」时先按标记切分：marker 之前的散文**立即
发出**（不拖首字延迟），marker 及其后进暂存。暂存上限 32KB / 200 帧，超限 fail-open
放行并记 WARN。`UpstreamStatus`（排队/额度控制流）直接放行**不补发**，否则会把
handler 的 `emitted` 置真、关掉流内排队与瞬时重开；普通断连则把非泄漏候选的暂存按
正文补发（不闷内容）。

覆盖范围：chat 流式 / chat 非流式 / responses 流式 / responses 非流式四条出口
（与 §4 的截断防护同一批链路）。**客户端没声明工具时整层直通**（不暂存、不还原、
不吞）——与 DSML 兜底同一口径：没有声明集合就无从校验白名单，宁可 fail-open 把文本
交给用户，也不凭空造出客户端不认识的 tool_calls。
### 4.3 上游 SSE 断帧重组（社区实测：帧被从 JSON 中间切断）

Qoder 网关（agent 端点与 api2-v2 都实测到）偶发把一帧的字节**从 JSON 中间切断、
注入裸换行**（约 3% 事件），续行可能没有 `data:` 前缀，甚至切在 `data:` 前缀内部
（`data\n: {...}`）。逐行读取时半截 JSON 解析失败 → 整帧被静默丢弃；丢的若是带
`id`/`name` 的工具头帧，客户端只剩参数增量（New API 侧报
`tool call delta is missing id or name`）。

处置（`_reframe_sse_lines`，参考 zenodinh/pi-provider-qoder#12 与
saulgoodgirl/QoderGateway#12）：

- **按空行分块、块内无分隔符拼接**：注入的裸换行不在原始载荷里（合法 JSON 不可能含
  裸换行），块内各行按原字节顺序直接相连才是原帧；**先拼接、后剥 `data:` 前缀**，
  所以切在前缀内部也能还原；
- **能独立解析的行即时放行**（不引入额外延迟）；解析不了的行缓存并拼后续行；
- **始终闭合不了的帧丢弃**并记 WARN + `sse.reframe` 事件（半截 JSON 绝不透传）：
  流末仍未决、单块超 1MB、或新行自身已是完整帧（旧块再也不会闭合）三种情形；
- 心跳/注释（`:`）、`event:`/`id:`/`retry:` 元数据行与 `[DONE]` 不受影响；
  `UpstreamStatus`（排队/额度）照常上抛，重组层不吞控制流。
### 5. 稳定物理设备指纹隔离 (`derive_id`)

双区域统一方案：以账号 UID + 业务盐单向 MD5 派生固定 `machineId` / `sessionId` / `machineType` / `machineToken`，COSY 签名头逐请求携带：

- **同一账号长期稳定**：出站请求永远来自同一台虚拟物理设备，规避机器码漂移风控；
- **多账号天然隔离**：不同账号机器码彼此独立，阻断跨账号关联检测。

### 6. 每日签到、额度与 Pro 福利包（官方能力门控：仅国内版）

- **每日签到**：`GET /sash/api/v1/me/daily-check-in/status` → 未签则 `POST …/claim`（+100 积分）；409 `ALREADY_CLAIMED` 归一化为「今日已签到」；上游活动停用（`status=DISABLED`）时诚实跳过、不硬领；签到后即时刷新额度快照；
- **国际版官方无签到接口**：国际版账号在任务中心、批量签到、调度器中均被自动门控，不会发起无效请求；国际版仍可查询 `quota/usage` 额度与 `user/plan` 套餐；
- **额度体系**：`/api/v2/quota/usage` 聚合基础额度 + 赠送/签到额度；`/api/v2/user/plan` 套餐名（Pro Trial 等）；
- **Pro 福利包**：一次性 +1800 积分，`eligibility → claim` 两步走（端点 404 时视为活动未开放）；
- **看板「签到与福利中心」**：连续签到天数、积分余额、福利包状态卡片 + 任务行表格，支持单账号/批量（仅国内视图显示，与官方能力一致）。

### 7. 后台常驻定时调度器 (Scheduler)

- **签到已移交 `qoder2api` 计划任务**（`D:\ai-servers\qoder2api\daily-checkin.ps1`，计划任务 `QoderDailyCheckin`，每日 10:01–10:15 随机时刻执行）。本网关**不执行任何签到**：两处签到只会争抢同一份每日额度（Qoder 按设备去重，重复领取返回 `SAME_PERSON_ALREADY_CLAIMED`）。看板「签到与福利中心」的按钮仍可手动单次触发，属排查用途；
- **每日 22:00**：集中 Token 保活 —— `drt-` → `deviceToken/refresh`，`jrt-` → `jobToken/refresh`，失败回落 PAT 重新交换；
- 任意巡检中对剩余寿命不足 4 小时的 Token 提前刷新；
- **会话死亡识别**：上游 `TOKEN_EXPIRE` / `12153` / `Offline user session not found` → 自动停用账号并标注需重新登录。

### 8. 凭证家族与生命周期

```
accessToken:   dt- (OAuth 设备流, ~30天)  或 jt- (PAT 交换, 24小时)
refreshToken:  drt- (~1年, 旋转)          或 jrt- (48小时)
personalToken: pt- (长期兜底, 看板导入)
```

刷新按 `refreshToken` 前缀路由，PAT 永不覆盖活跃 OAuth 会话，只做最终兜底；`access token` 轮换后 COSY 会话自动重建。

---

## 三、账号添加与管理

打开看板 `http://127.0.0.1:8790/`，在「账号」区域操作：

### 方式零：扫描本机已登录凭证（推荐，双区）
1. 点击 **「扫描本地凭证」**（只读，不写入）；
2. 弹窗分区域列出检测到的凭证：
   - **桌面 App**：`%APPDATA%\com.qoder[.cn].app.stable\auth.v1.dat`
     （Chromium `v10` 布局，`Local State` 的 os_crypt 密钥经 DPAPI 解出后 AES-256-GCM 解密）
   - **Qoder CLI**：`~/.qoder[.cn]/.auth/user[.{profile}]`
     （AES-128-CBC，key = `machine_id` 前 16 字符）
3. 点击对应行的 **「导入」**（或启动时日志只会提示发现 N 条、绝不静默采用）。

### 方式一：OAuth 设备授权（推荐，免客户端）
1. 点击 **「+ 添加账号 (OAuth)」**；
2. 选择登录区域（国内版 / 国际版），点击弹出的官方授权链接；
3. 浏览器完成登录授权（PKCE S256），网关自动轮询取回 `dt-`/`drt-` 并入池。

### 方式二：PAT 导入
1. 在 Qoder 网页版「设置 → Personal Access Token」创建 `pt-` 令牌；
2. 看板点击 **「🔑 导入 PAT」**，选择区域并粘贴；
3. 网关自动交换 `jt-`/`jrt-`、拉取账号身份入池。

### 方式三：JSON 导入 / 导出
- 支持全量/单账号导出（可选带密钥）、Dry-Run 预检导入、覆盖同 UID；
- 兼容本网关导出格式、账号数组、单个账号对象。

---

## 四、客户端配置与接入

### OpenAI 兼容客户端 (Chatbox / NextChat / Cherry Studio / Kelivo 等)
- **API 接口地址 (Base URL)**：`http://127.0.0.1:8790/v1`（局域网为 `http://<局域网IP>:8790/v1`）
- **API Key**：
  - 本机单机模式（未配置 Key 且未开 LAN）：可留空或填任意字符；
  - 已配置 Key 或 LAN 模式：在看板「设置」添加或复制已绑定出口的 Key。
- **模型名称**：填 `/v1/models` 列出的 **`id`（官方模型名，如 `Qwen3.8-Max`）** —— 这是唯一需要记的值；`upstream_key`（缩写 key）、人类别名（`qwen3.8-max`）与官方本地化名也全部可解析。

### Codex CLI / Claude Code (Responses API)
```bash
export OPENAI_BASE_URL="http://127.0.0.1:8790/v1"
export OPENAI_API_KEY="你在看板设置中添加并绑定的API_Key"
```
custom freeform 工具（`apply_patch`）自动降级为 function 工具出站、入站还原为 `custom_tool_call`，Codex 工具回路完整可用。

---

## 五、看板与接口一览

访问 `http://127.0.0.1:8790/` 即可使用集成看板，核心接口：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | / | Web 用量与任务监控看板 |
| POST | /v1/chat/completions | 标准 Chat Completions 接口 |
| POST | /v1/responses | Responses API 协议接口 |
| GET | /v1/models | 模型列表（动态拉取 + 静态兜底，含能力与规格宣告） |
| GET | /tasks | 签到状态、连续天数、福利包资格与额度快照 |
| POST | /tasks/run | 触发批量每日签到与领奖 |
| POST | /tasks/travel | 批量领取 Pro 福利包 |
| GET | /scheduler | 定时调度器运行状态与排程日志 |
| POST | /scheduler/trigger | 手动立即执行后台巡检保活 |
| POST | /accounts/login/start | 发起 OAuth 设备授权 |
| POST | /accounts/import/pat | 导入 PAT 令牌 |
| POST | /accounts/checkin | 手动签到（单个/全部） |

---

## 六、开发与测试

```bash
# 离线确定性测试（AES-128/256 向量与官方 fixture KAT、QMC/凭证解密、
# 自定义 B64、COSY 签名、双区官方目录全字段（峰谷价/多窗口/思考档位/展示 id/解析）、
# 独占路由、签到能力门控与 DISABLED 归一化、请求体（含工具语境隔离）、信封解包、
# custom 工具转译、截断 tool_call 防护（四条链路）、DSML 文本兜底、
# 泄漏文本回读（五形态 + 误伤）、SSE 断帧重组、本机凭证扫描）
python _test_qoder.py

# 直接启动
python qoder_proxy.py --port 8790

# 端到端模型库/能力清单验证（网关运行中执行；逐模型对比官方"此刻"数据：
# id/enable/峰谷价/上下文窗口/思考档位/官方介绍/禁用原因/不编造字段/低谷判定）
#   基准 = 官方动态接口优先（与桌面版选择器同源），本机目录按字段兜底
python _verify_models.py --base http://127.0.0.1:8790
#   313 项断言；退出码 0=全部一致；1=存在差异（打印逐条 FAIL 明细）；2=网关不可达
```

模块结构：

| 文件 | 职责 |
|---|---|
| `qoder_proxy.py` | 主网关：HTTP 路由、COSY 数据面、双协议转换、用量统计、看板鉴权 |
| `qoder_sign.py` | 自定义 Base64、纯库 AES-128/256 + GCM、RSA、DPAPI、QMC 解密、COSY 签名 |
| `qoder_accounts.py` | 双区账号池、OAuth 设备流、PAT、Token 生命周期、**本机凭证扫描/导入** |
| `qoder_catalog.py` | 双区官方模型快照（源自本机解密的官方 catalog）、别名与独占表 |
| `qoder_tasks.py` | 签到闭环（含 DISABLED 归一化）、Pro 福利包、批量执行、保活巡检 |
| `qoder_scheduler.py` | 整点排程调度器（09/21 签到 · 22:00 保活，签到按区域门控） |
| `qoder_settings.py` | 面板密码 (PBKDF2)、多 API Key 出口绑定、会话管理 |
| `qoder_fingerprint.py` | UID 稳定设备指纹派生 (derive_id) |
| `baseprompt.json` | 官方推理请求体模板 |
| `dashboard.html` | 单文件 Web 看板（本地凭证两步扫描导入 + PAT 导入） |

---

## 七、致谢与引用声明 (Credits & References)

本项目在协议兼容、COSY 签名与设备授权链路设计中，深度参考了开源社区现有项目的经验与逆向成果，特此致谢：

- **[mmqz/cpa-multi-plugins](https://github.com/mmqz/cpa-multi-plugins)**：
  - **Qoder 双区域合并插件**：CN/Intl 常量表、OAuth 设备授权与 PAT 交换流程、COSY 签名与自定义 Base64 编码的验证实现；
  - **每日签到与保活排程设计**（本网关保留 22:00 保活；签到改由 `qoder2api` 计划任务承担）、按 token 前缀路由的刷新策略。
- **[Liki4/qodercli2api](https://github.com/Liki4/qodercli2api)**：
  - **Qoder OAuth 与推理协议逆向全记录**：设备流 PKCE 细节、`deviceToken`/`jobToken` 端点、SSE 信封与 `[DONE]`/`event:finish` 语义。
- **[Sliverkiss/workbuddy2api](https://github.com/Sliverkiss/workbuddy2api)**：
  - **设备指纹稳定派生设计 (`derive_id`)**、整点排程调度理念、指纹脱敏管线与 DeepSeek 多轮思维链回填。
- **WorkBuddy2API-Hub**：本项目的架构、看板交互与功能矩阵蓝本。

---

## 八、免责声明 (Disclaimer)

1. 本项目为非官方自托管网关，仅供技术研究、逆向协议学习与个人合法授权账号在私有环境测试使用。
2. 本项目不提供任何账号及额度。请严格遵守官方服务条款，禁止用于任何商业转售、恶意并发或违规滥用。
