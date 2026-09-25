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

## 3. 限流与锁定

- 按来源（请求端 IP）统计**连续**登录失败；达到 `MAX_FAILED_ATTEMPTS`
  （默认 5）次后锁定该来源 `LOCKOUT_SECONDS`（默认 300）秒。
- 锁定期内所有登录一律拒绝，**即使口令正确**；锁定期满后自动解除并重新计数。
- 一次登录成功立即清零失败计数。
- 计数变更全部在同一把锁内完成：并发失败请求精确计入（不漏计、不重复计）。
- **信息不泄露**：用户不存在、口令错误、来源锁定对外均返回相同的
  `401 {"detail":"invalid credentials"}`；用户不存在时也执行一次假盐
  PBKDF2 以拉平耗时；响应与日志中不出现明文口令或凭证，日志仅记录来源、
  主体与凭证指纹。

## 4. 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/login` | 体 `{username,password}`；成功返回 `{token,expires_at}`，失败统一 401 |
| POST | `/refresh` | 体 `{token}`；成功返回新凭证，失败 401 且 detail 为 expired/revoked/replayed/unknown |
| POST | `/logout` | 体 `{token}`；撤销凭证，204 |
| GET  | `/protected/documents` | 需 `documents:read`（Bearer 令牌） |
| POST | `/protected/documents` | 需 `documents:write` |

## 5. 配置项

均可通过环境变量覆盖（见 `app/config.py` / `app/deps.py`）：

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `SESSION_TTL_SECONDS` | `3600` | 会话凭证有效期（秒） |
| `MAX_FAILED_ATTEMPTS` | `5` | 触发锁定的连续失败次数 |
| `LOCKOUT_SECONDS` | `300` | 锁定时长（秒） |
| `REPLAY_GRACE_SECONDS` | `1` | 轮换后区分并发竞争与事后重放的宽限窗口（秒） |

## 6. 代码结构

```
app/models.py        数据模型与拒绝原因枚举
app/config.py        配置项
app/tokens.py        凭证生成 / 哈希 / 指纹
app/session_store.py 凭证存储：签发、轮换（加锁原子）、撤销、原因分类
app/authz.py         角色注册表、层级/通配覆盖判定、可解释结论
app/rate_limit.py    失败计数与来源锁定
app/service.py       用例组合层：登录、刷新、登出、授权
app/deps.py          FastAPI 依赖与服务单例
app/routes.py        HTTP 接口
tests/               生命周期/并发、权限、限流锁定、HTTP 集成测试
```
