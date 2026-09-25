# 会话认证与访问控制（fastapi-session-authz）

在本地 FastAPI 服务上扩展的会话认证与访问控制能力，保证凭证签发、轮换、
撤销与权限判定在并发与异常情况下结论一致且可解释。

## 权限模型

- **权限** 表示为 `动作:资源路径`，如 `read:docs/team-a/report`。
  资源是按 `/` 分段的层级路径。
- **角色** 是一组权限授予（grant）。授予侧支持两种宽松形式：
  - 层级前缀：授予 `read:docs` 覆盖 `read:docs/a/b`（段边界对齐的前缀）；
  - 通配符：授予 `*:admin` 形式 `*:*` 覆盖一切。
- **最小权限原则**：只允许“授予覆盖请求”，不允许“请求放大授予”：
  - 授予 `write:docs/team-a` 不覆盖 `write:docs`（向父级放大），
    也不覆盖 `write:docs/team-b`（横向越权）；
  - 请求侧携带 `*` 时只允许与授予逐字相等，不得用通配请求套取更大范围。
- **立即生效**：判定时实时读取角色定义与角色成员关系，不做任何缓存；
  权限变更或凭证撤销后，后续请求立即按新状态判定。

## 凭证生命周期

```
issue ──> ACTIVE ──refresh──> ROTATED（旧凭证被消费，签发新 ACTIVE 凭证）
           │  └────────────> （再次使用旧凭证 = REPLAYED，拒绝）
           ├──logout/revoke──> REVOKED
           └──now > expires_at──> EXPIRED（惰性判定）
```

- **签发**：登录成功或轮换时生成新凭证，携带主体、角色快照与过期时间。
- **轮换单次使用**：`refresh` 在同一临界区内完成“校验旧凭证 + 置为
  ROTATED + 登记新凭证”，因此并发到达的刷新请求最多一个成功，
  其余得到 `session_replayed`，绝不会产生两个同时生效的新凭证。
- **撤销**：`logout` 将凭证置为 REVOKED，立即生效。
- **过期**：读取时惰性判定，状态一旦离开 ACTIVE 不可逆。
- **拒绝原因可区分**：

| 场景 | HTTP | error code |
|---|---|---|
| 凭证过期 | 401 | `session_expired` |
| 凭证已撤销 | 401 | `session_revoked` |
| 凭证被重放（轮换后再次使用） | 401 | `session_replayed` |
| 凭证不存在 | 401 | `session_invalid` |
| 权限不足 | 403 | `forbidden` |
| 触发限流锁定 | 429 | `rate_limited` |
| 登录失败 | 401 | `invalid_credentials` |

## 限流与锁定

- 以来源（客户端 IP）为键，统计失败窗口内的连续失败次数；
  登录失败与刷新/敏感操作被拒绝都计入同一来源键。
- 连续失败达到 `max_failed_attempts` 即锁定 `lockout_seconds`，
  锁定期内一律拒绝（包括口令本正确的请求），且锁定期内的失败
  不重复计数、不延长锁定。
- 锁定期满后状态自动清零恢复；任何一次成功也会清零计数。
- 计数与锁定判定在同一把锁内完成：并发失败各自恰好计数一次，
  不会漏计绕过阈值，也不会重复计数。

## 敏感信息保护

- 登录失败对外统一为 `invalid_credentials`，不区分“用户不存在”与
  “口令错误”；用户不存在时用哑值参与口令比较，避免时间侧信道。
- 日志只记录请求输入的非敏感部分（用户名、来源、所需权限、命中授予、
  最终结论），凭证一律以 SHA-256 指纹前缀出现，绝不记录明文口令或
  完整令牌。

## 配置项（`app/config.py` 的 `Settings`）

| 配置项 | 默认值 | 含义 |
|---|---|---|
| `session_ttl_seconds` | 3600 | 会话凭证有效期（秒） |
| `max_failed_attempts` | 5 | 触发锁定的连续失败阈值 |
| `lockout_seconds` | 300 | 锁定时长（秒） |
| `failure_window_seconds` | 600 | 失败计数窗口，超窗失败不计入 |

## HTTP 接口

- `POST /login` `{username, password}` → `{token}`
- `POST /refresh` `{token}` → `{token}`（旧凭证同时失效）
- `POST /logout` `{token}` → 撤销凭证
- `POST /authorize` `{token, action, resource}` → `{subject, verdict}`

## 运行与测试

```bash
uv run python main.py     # 启动服务（127.0.0.1:8000）
uv run pytest tests/ -q   # 运行测试（重放/并发刷新/过期/撤销/越权/锁定边界）
uv run pytest tests/ -s   # 查看每条请求的审计日志：输入、判定依据、结论
```
