# 会话认证与访问控制（FastAPI）

在最小 FastAPI 骨架上扩展的会话认证与访问控制能力，覆盖凭证签发 / 轮换 /
撤销、基于角色与资源层级的权限判定，以及登录失败限流与锁定。核心目标：
**并发与异常场景下结论一致、原因可区分，且不泄露敏感信息。**

## 运行与测试

```bash
uv sync
uv run uvicorn main:app            # 启动服务（启动时内置 alice/bob 演示账号）
uv run pytest                      # 运行全部测试（日志随测试输出 AUDIT 审计行）
```

演示账号：`alice/alice-pw`（viewer）、`bob/bob-pw`（editor）。

## 1. 权限模型

权限串格式为 `resource:action`：

- **资源层级**：resource 以 `/` 分层，如 `documents/reports/2026`。
  授予按层级向下继承——持有 `documents:read` 即覆盖 `documents/reports:read`；
  但更具体的授予**不得向上放大**，`documents/reports:read` 不覆盖 `documents:read`。
- **通配**：授予某一段为 `*` 匹配该层任意单段（`documents/*:read` 匹配
  `documents/reports:read`）；action 为 `*` 匹配任意动作；`*:*` 为全局管理员。
- **最小权限比对**：判定时逐条检查授予是否覆盖所需权限，命中即放行，
  全部不覆盖则拒绝。结论 `AuthzDecision` 包含 `required / granted /
  matched_grant / explanation`，说明命中依据或拒绝原因。
- **角色**：`RoleRegistry.define_role(role, grants)` 定义角色拥有的授予；
  会话主体在**每次请求时实时读取**当前角色与角色定义，判定结果不缓存：
  角色变更、角色定义收紧、会话撤销均在下一次请求立即生效。

## 2. 凭证生命周期

- 凭证为 32 字节密码学随机串（`secrets.token_urlsafe`），明文仅在签发响应中
  出现一次；服务端只存 SHA-256 哈希，日志只打印哈希前 12 位指纹。
- **签发**：登录成功创建 ACTIVE 凭证，含签发时刻、过期时刻与轮换链 `family_id`。
- **过期**：`expires_at <= now` 即拒绝，原因 `expired`。
- **轮换（refresh）**：成功轮换时旧凭证原子变为 ROTATED 并签发同链新凭证。
  “检查旧凭证 + 作废 + 签发新凭证”在同一把锁内完成，并发到达的刷新请求
  **恰好只有一个成功**，其余以 `replayed` 拒绝。
  - 轮换后 `REPLAY_GRACE_SECONDS`（默认 1 秒）内的旧凭证使用视为**并发竞争**：
    拒绝但保留胜出的新链。
  - 宽限窗口之外的旧凭证使用视为**事后重放（疑似被盗）**：拒绝并**撤销整条
    轮换链**。
- **撤销**：登出撤销当前凭证；`revoke_subject` 可撤销主体全部会话，
  权限变更场景可直接调用。
- **三类拒绝原因可区分**：`expired`（过期）、`revoked`（已撤销）、
  `replayed`（被重放），另有 `unknown`（未知凭证）。撤销与过期同时成立时
  稳定归为 `revoked`。

## 3. 统一来源风险准入（限流与渐进式锁定）

登录、**凭证换发（refresh）**、**凭证注销（logout）** 属于同一类敏感操作，
统一经过来源风险准入（`RateLimiter.gate(source)`），同一来源（请求端 IP）
共享**同一份失败计数、锁定状态与升级等级**。

### 3.1 准入范围与结论区分

- 每次敏感操作先做来源准入，再触碰任何凭证状态：来源处于锁定期内时，
  换发/注销**直接拒绝**——不会产生新凭证，也不会把旧凭证置为
  ROTATED/REVOKED。
- 准入通过后：登录口令错误、换发命中 `expired/revoked/unknown` 或
  **宽限窗口外疑似被盗的重放（stolen）**、注销遇到未知凭证，均计入该来源
  一次失败；换发在宽限窗口内的**并发竞争重放（racing）**视为良性时序、
  不计风险；对已撤销凭证重复注销幂等、不计风险。敏感操作成功即清零当前
  失败计数。
- 调用方可区分两类拒绝：限流拒绝为 `RejectReason.RATE_LIMITED`
  （HTTP 层换发/注销返回 **429** `{"detail":"too many requests"}`），
  凭证拒绝仍为 `expired/revoked/replayed/unknown`（HTTP 401）。
- **信息不泄露**：锁定期间的换发/注销不读取、不判定凭证，响应体与是否
  存在有效凭证无关；登录锁定、用户不存在、口令错误对外仍是**相同**的
  `401 {"detail":"invalid credentials"}`；用户不存在时也执行一次假盐
  PBKDF2 拉平耗时；响应与日志中不出现明文口令或凭证，日志仅记录来源、
  主体、操作与凭证指纹（限流拒绝行不带凭证指纹）。

### 3.2 渐进式锁定与平稳恢复

- 同一来源连续失败达到 `MAX_FAILED_ATTEMPTS`（默认 5）次触发一次锁定；
  **连续多次触发锁定时，每次时长比上一次更长**：
  `LOCKOUT_SECONDS × LOCKOUT_MULTIPLIER^level`，直到
  `MAX_LOCKOUT_SECONDS` 封顶（默认 300s 基础、2 倍递增、3600s 封顶）。
- 锁定期内的请求一律拒绝、**不计数也不续期**；锁定期满自动解除并清零
  失败计数，恢复后的第一次正常操作照常成功。
- **平稳恢复**：从最近一次锁定期满起，连续 `CALM_SECONDS`（默认 86400s）
  没有新的失败触发，升级等级回到基础档（level=0）重新计数；平稳期内
  再次触发锁定则在当前等级上继续递增。
- 同一来源的敏感操作由固定 **64 道条带锁**（来源经 crc32 稳定映射）串行化，
  “准入判定 → 失败计入 → 凭证变更”处于同一串行区间，锁序恒为
  条带锁→内部锁：锁定期内不会放行、刚清零的计数不会被旧请求写回、
  锁定期不会被反复续上。

### 3.3 有界的状态管理

- 风险状态表最多保留 `MAX_TRACKED_SOURCES`（默认 10000）个来源，内存不随
  请求量无限增长；从未失败过的正常操作不留任何状态。
- **闲置回收**：计数为零、未锁定、且升级等级已过平稳期的来源，在后续
  准入/失败登记时按**来源键排序后确定性删除**（结果可复现）；区间结束后
  的空占位立即移除；成功归零且已过平稳期的来源立即移除。
- 仍在锁定期内的来源、正在累计失败序列的来源、以及升级等级仍在平稳窗口内
  的来源**绝不会被提前回收/放行/清零**；正处于准入区间的来源以
  `in_gate` 标记保护。
- 容量打满且无闲置可回收时（即所有在表来源都仍有风险），新失败被保安全
  丢弃并告警，状态表严格不超上限。

## 4. 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/login` | 体 `{username,password}`；成功返回 `{token,expires_at}`，失败统一 401（锁定不单独暴露） |
| POST | `/refresh` | 体 `{token}`；成功返回新凭证；凭证原因 401（expired/revoked/replayed/unknown），来源锁定 429 |
| POST | `/logout` | 体 `{token}`；撤销凭证，204；来源锁定 429（凭证不变）；重复注销幂等 |
| GET  | `/protected/documents` | 需 `documents:read`（Bearer 令牌） |
| POST | `/protected/documents` | 需 `documents:write` |

## 5. 配置项

均可通过环境变量覆盖（见 `app/config.py` / `app/deps.py`）：

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `SESSION_TTL_SECONDS` | `3600` | 会话凭证有效期（秒） |
| `MAX_FAILED_ATTEMPTS` | `5` | 触发锁定的连续失败次数（登录/换发/注销共享） |
| `LOCKOUT_SECONDS` | `300` | 基础锁定时长（秒，第 1 档） |
| `LOCKOUT_MULTIPLIER` | `2` | 每升一档锁定时长的递增倍数 |
| `MAX_LOCKOUT_SECONDS` | `3600` | 单次锁定时长上限（秒），递增到此封顶 |
| `CALM_SECONDS` | `86400` | 平稳期（秒）：距最近一次锁定期满无新失败后，等级回基础档 |
| `MAX_TRACKED_SOURCES` | `10000` | 风险状态表保留的来源数量上限 |
| `REPLAY_GRACE_SECONDS` | `1` | 轮换后区分并发竞争与事后重放的宽限窗口（秒） |

## 6. 兼容性与本地验证

**兼容范围**：登录、轮换、撤销、层级权限判定与并发刷新的既有行为保持不变；
登录锁定仍对外返回统一 401。本次增量为：换发/注销新增来源准入（锁定期
返回 429）；`RejectReason` 新增 `rate_limited`；服务层 `refresh/logout`
新增 `source`（注销默认 `unknown`），注销返回值由 `bool` 升级为
`LogoutResult{ok,changed,reason}`。

```bash
uv sync
uv run pytest                      # 全部单测（AUDIT 审计行随日志输出）
uv run pytest tests/test_risk_gate.py                  # 仅新增风控用例
LOCKOUT_SECONDS=60 LOCKOUT_MULTIPLIER=3 \
  MAX_LOCKOUT_SECONDS=1800 CALM_SECONDS=3600 \
  MAX_TRACKED_SOURCES=5000 uv run uvicorn main:app     # 自定义锁定策略启动
```

测试日志中的每个用例以
`AUDIT action=... | input=... | basis=... | conclusion=...` 展示请求输入、
命中的判定依据与最终结论；另有自动校验确保任何日志行都不出现明文凭证或
口令（见 `tests/conftest.py`）。

## 7. 代码结构

```
app/models.py        数据模型与拒绝原因枚举（含 rate_limited、LogoutResult）
app/config.py        配置项（阈值/基础时长/倍数/上限/平稳期/容量）
app/tokens.py        凭证生成 / 哈希 / 指纹
app/session_store.py 凭证存储：签发、轮换（加锁原子）、撤销、原因分类、重放模式
app/authz.py         角色注册表、层级/通配覆盖判定、可解释结论
app/rate_limit.py    统一来源风险准入、渐进式锁定/平稳恢复、有界状态回收
app/service.py       用例组合层：登录/换发/注销经 gate，授权实时判定
app/deps.py          FastAPI 依赖与服务单例
app/routes.py        HTTP 接口（锁定 429 / 凭证原因 401 / 登录统一 401）
tests/               生命周期/并发、权限、限流锁定、风险准入、HTTP 集成测试
```
