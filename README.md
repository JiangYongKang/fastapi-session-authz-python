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

## 3. 来源风险准入（限流与渐进锁定）

登录失败、凭证换发（refresh）、凭证注销（logout）三类敏感操作**共享同一来源
的同一份风险计数与锁定状态**：任一操作失败都会推高该来源的计数，达到阈值即
锁定整个来源。

- **统一准入**：来源锁定期间，登录、换发、注销一律在入口处直接拒绝。
  换发被拒时**不检查凭证、不产生新凭证、不改动任何现有凭证状态**；
  注销同理。拒绝原因 `rate_limited` 与凭证类原因
  （`expired`/`revoked`/`replayed`/`unknown`）在调用方层面可区分；
  HTTP 层换发/注销在锁定时返回 `429 rate_limited`，登录仍返回统一的
  `401 invalid credentials`（不暴露锁定状态、用户是否存在、凭证是否有效）。
- **计数规则**：达到 `MAX_FAILED_ATTEMPTS`（默认 5）次失败即锁定
  `LOCKOUT_SECONDS`（默认 300）秒。任一操作成功清零失败计数。
  唯一例外：轮换宽限窗口内的旧凭证重复使用属于**良性并发竞争**
  （`replayed`/`racing`），拒绝但不计入风险；窗口之外的事后重放
  （疑似被盗）照常计入。
  锁定期间到达的失败**如实计入，但绝不延长当前锁定期**
  （`locked_until` 一旦设定不滑动）；锁定期满结算时，若期间累计失败仍达
  阈值，则按升级后的时长开启一次**新**锁定，否则清零恢复。
- **渐进锁定**：同一来源连续第 n 次锁定的时长为
  `min(LOCKOUT_SECONDS * LOCKOUT_MULTIPLIER^n, LOCKOUT_MAX_SECONDS)`
  （默认倍数 2、上限 3600 秒），逐级递增直到上限。
- **平稳恢复**：连续 `CALM_SECONDS`（默认 900 秒）没有任何新失败后，
  递增级别回落，下一次锁定重新从基础时长计起。
- **有界状态**：被记录的来源数量上限为 `MAX_SOURCES`（默认 10000）。
  新来源入场时先回收闲置超过 `SOURCE_IDLE_SECONDS`（默认 3600 秒）且未锁定
  的来源；仍满则按确定性规则淘汰：**锁定中的来源绝不淘汰**（不会提前放行），
  其余按“未决失败数最少 → 最后活动最旧 → 来源名字典序”选择，
  正在累计的失败序列因此被优先保护。若容量全部被锁定中的来源占满，
  新来源的失败无法计数（有界降级，日志告警），但不会被误判为已锁定。
  回收与淘汰只取决于事件序列与时间戳，可复现。
- **并发一致性**：所有计数与状态变更在同一把锁内完成——锁定期内不会被
  放行；并发失败精确计入（不漏计、不重复计）；清零后的计数不会被旧请求
  写回（读写都在锁内串行）。
- **信息不泄露**：用户不存在、口令错误、来源锁定对登录调用方表现一致；
  用户不存在时也执行一次假盐 PBKDF2 以拉平耗时；响应与日志中不出现明文
  口令或凭证，日志仅记录来源、主体与凭证指纹。

## 4. 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/login` | 体 `{username,password}`；成功返回 `{token,expires_at}`，失败统一 401 |
| POST | `/refresh` | 体 `{token}`；成功返回新凭证；凭证类失败 401 且 detail 为 expired/revoked/replayed/unknown；来源锁定时 429 且 detail 为 rate_limited |
| POST | `/logout` | 体 `{token}`；撤销凭证，204（不区分凭证是否存在）；来源锁定时 429 且 detail 为 rate_limited |
| GET  | `/protected/documents` | 需 `documents:read`（Bearer 令牌） |
| POST | `/protected/documents` | 需 `documents:write` |

## 5. 配置项

均可通过环境变量覆盖（见 `app/config.py` / `app/deps.py`）：

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `SESSION_TTL_SECONDS` | `3600` | 会话凭证有效期（秒） |
| `MAX_FAILED_ATTEMPTS` | `5` | 触发锁定的连续失败次数（登录/换发/注销共享） |
| `LOCKOUT_SECONDS` | `300` | 基础锁定时长（秒） |
| `REPLAY_GRACE_SECONDS` | `1` | 轮换后区分并发竞争与事后重放的宽限窗口（秒） |
| `LOCKOUT_MULTIPLIER` | `2` | 连续锁定时长的递增倍数 |
| `LOCKOUT_MAX_SECONDS` | `3600` | 单次锁定时长上限（秒） |
| `CALM_SECONDS` | `900` | 平稳期：无新失败多久后递增级别回落（秒） |
| `MAX_SOURCES` | `10000` | 被记录风险状态的来源数量上限 |
| `SOURCE_IDLE_SECONDS` | `3600` | 来源闲置多久后其状态可被回收（秒） |

## 6. 兼容范围与本地验证

- **兼容范围**：凭证生命周期（签发/轮换/撤销/重放检测）、权限模型与判定
  接口、`/login` 的对外行为保持不变；`/refresh`、`/logout` 仅在来源锁定
  时新增 `429 rate_limited` 响应，其余状态码与响应体不变。服务层
  `refresh`/`logout` 签名新增 `source`/`now` 参数（进程内 API，非 HTTP
  契约）。新配置项均有默认值，不设置环境变量即可按默认策略运行。
- **本地验证**：

  ```bash
  uv sync
  uv run pytest            # 全部用例；AUDIT 行展示每类业务的输入/依据/结论
  uv run pytest tests/test_risk_admission.py -o log_cli=true -o log_cli_level=INFO
  uv run uvicorn main:app  # 本地启动，手工验证 429/401 行为
  ```

## 7. 代码结构

```
app/models.py        数据模型与拒绝原因枚举
app/config.py        配置项
app/tokens.py        凭证生成 / 哈希 / 指纹
app/session_store.py 凭证存储：签发、轮换（加锁原子）、撤销、原因分类
app/authz.py         角色注册表、层级/通配覆盖判定、可解释结论
app/rate_limit.py    来源风险准入：共享计数、渐进锁定、平稳恢复、有界状态
app/service.py       用例组合层：登录、换发、注销、授权（敏感操作统一过风险准入）
app/deps.py          FastAPI 依赖与服务单例
app/routes.py        HTTP 接口
tests/               生命周期/并发、权限、风险准入（锁定/渐进/容量）、HTTP 集成测试
```
