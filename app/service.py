"""认证与授权服务：组合凭证存储、权限注册表与来源风险准入，对外提供用例级接口。

敏感操作（登录 / 凭证换发 / 凭证注销）统一经过 ``RateLimiter.gate``：
同一来源共享风险计数与锁定状态；锁定期内的敏感操作在触碰凭证之前就被
拒绝（不产生新凭证、不改动现有凭证）。限流原因 ``rate_limited`` 与凭证
原因（expired/revoked/replayed/unknown）对调用方可区分，但对外 HTTP
响应与日志均不暴露凭证是否有效、用户是否存在。
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time

from app.authz import RoleRegistry
from app.config import Settings
from app.models import (
    AuthzDecision,
    IssuedToken,
    LogoutResult,
    RefreshResult,
    RejectReason,
)
from app.rate_limit import RateLimiter
from app.session_store import SessionStore
from app.tokens import fingerprint

logger = logging.getLogger("authz.service")

_PBKDF2_ITERATIONS = 100_000
# 用户不存在时也对假盐做一次哈希，避免通过耗时差异探测用户是否存在
_DUMMY_SALT = b"authz-dummy-salt"


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS
    ).hex()


class AuthService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.sessions = SessionStore(settings)
        self.roles = RoleRegistry()
        self.limiter = RateLimiter(settings)
        self._lock = threading.Lock()
        self._users: dict[str, tuple[str, frozenset[str]]] = {}  # name -> (口令哈希, 角色)

    # ---- 用户目录（演示用内存实现） ----

    def register_user(self, username: str, password: str, roles: list[str]) -> None:
        salt = secrets.token_bytes(16)
        stored = f"{salt.hex()}${_hash_password(password, salt)}"
        with self._lock:
            self._users[username] = (stored, frozenset(roles))

    def update_user_roles(self, username: str, roles: list[str]) -> None:
        """变更用户角色：后续请求的权限判定立即使用新角色（判定不缓存）。"""
        with self._lock:
            entry = self._users.get(username)
            if entry is None:
                raise KeyError(username)
            self._users[username] = (entry[0], frozenset(roles))
        logger.info("roles updated subject=%s roles=%s", username, sorted(roles))

    def _verify_password(self, username: str, password: str) -> bool:
        with self._lock:
            entry = self._users.get(username)
        if entry is None:
            _hash_password(password, _DUMMY_SALT)  # 拉平耗时
            return False
        salt_hex, expected = entry[0].split("$", 1)
        actual = _hash_password(password, bytes.fromhex(salt_hex))
        return hmac.compare_digest(actual, expected)

    def _roles_of(self, username: str) -> frozenset[str] | None:
        with self._lock:
            entry = self._users.get(username)
            return entry[1] if entry else None

    # ---- 敏感操作用例（统一来源风险准入） ----

    def login(
        self, source: str, username: str, password: str, now: float
    ) -> IssuedToken | None:
        """登录：来源准入 -> 校验口令 -> 签发会话。

        锁定、口令错误、用户不存在对外表现一致（均返回 None）；
        准入区间与口令校验同来源串行。日志只记录来源与指纹，
        绝不记录明文口令或凭证。
        """
        with self.limiter.gate(source, now) as held:
            if not held.admitted:
                logger.warning(
                    "login rejected reason=rate_limited source=%s", source
                )
                return None
            if not self._verify_password(username, password):
                triggered = held.report_failure(now)
                logger.warning(
                    "login rejected reason=bad_credentials source=%s lockout=%s",
                    source, triggered,
                )
                return None
            held.report_success()
            roles = self._roles_of(username) or frozenset()
            token = self.sessions.issue(username, roles, now)
            logger.info(
                "login ok subject=%s source=%s token_fp=%s",
                username, source, fingerprint(token.plaintext),
            )
            return token

    def refresh(
        self, plaintext: str, now: float, source: str = "unknown"
    ) -> RefreshResult:
        """凭证换发：来源准入 -> 原子轮换。

        锁定期内直接拒绝，且先于任何凭证检查：不产生新凭证、旧凭证状态不变。
        凭证原因（过期/已撤销/未知）与疑似被盗重放计入来源失败计数；
        宽限窗口内的并发竞争重放不计入。
        """
        with self.limiter.gate(source, now) as held:
            if not held.admitted:
                logger.warning(
                    "refresh rejected reason=rate_limited source=%s", source
                )
                return RefreshResult(ok=False, reason=RejectReason.RATE_LIMITED)
            result = self.sessions.refresh(plaintext, now)
            if result.ok:
                held.report_success()
            elif (
                result.reason == RejectReason.REPLAYED
                and result.replay_mode == "racing"
            ):
                # 并发竞争的重复使用是良性时序，不记为来源风险
                logger.info(
                    "refresh racing not counted source=%s token_fp=%s",
                    source, fingerprint(plaintext),
                )
            else:
                held.report_failure(now)
                logger.warning(
                    "refresh failure counted source=%s reason=%s",
                    source, result.reason.value if result.reason else "unknown",
                )
            return result

    def logout(
        self,
        plaintext: str,
        source: str = "unknown",
        now: float | None = None,
    ) -> LogoutResult:
        """凭证注销：来源准入 -> 撤销。锁定期内拒绝且不改动凭证状态。

        成功撤销返回 changed=True；对已撤销凭证重复注销幂等（不计风险）；
        未知凭证视为攻击尝试，计入来源失败。
        """
        if now is None:
            now = time.time()
        with self.limiter.gate(source, now) as held:
            if not held.admitted:
                logger.warning(
                    "logout rejected reason=rate_limited source=%s", source
                )
                return LogoutResult(ok=False, reason=RejectReason.RATE_LIMITED)
            changed = self.sessions.revoke(plaintext)
            if changed:
                held.report_success()
                logger.info(
                    "logout ok source=%s token_fp=%s", source, fingerprint(plaintext)
                )
                return LogoutResult(ok=True, changed=True)
            reason = self.sessions.classify(plaintext, now)
            if reason == RejectReason.UNKNOWN:
                held.report_failure(now)
            logger.warning(
                "logout rejected reason=%s source=%s token_fp=%s",
                reason.value if reason else "unknown", source, fingerprint(plaintext),
            )
            return LogoutResult(ok=False, changed=False, reason=reason)

    # ---- 权限判定（非敏感写操作，不走来源准入） ----

    def authorize(self, plaintext: str, required: str, now: float) -> AuthzDecision:
        """权限判定：凭证无效或权限不足均拒绝，结论含命中依据。

        角色实时从用户目录读取：权限变更后无需等待，立即生效。
        """
        record = self.sessions.validate(plaintext, now)
        if record is None:
            reason = self.sessions.classify(plaintext, now)
            logger.warning(
                "authorize rejected reason=%s required=%s token_fp=%s",
                reason.value if reason else "unknown",
                required, fingerprint(plaintext),
            )
            return AuthzDecision(
                allowed=False,
                required=required,
                granted=(),
                explanation=f"credential rejected: {reason.value if reason else 'unknown'}",
            )
        roles = self._roles_of(record.subject)
        if roles is None:
            logger.warning(
                "authorize rejected reason=subject_gone subject=%s", record.subject
            )
            return AuthzDecision(
                allowed=False,
                required=required,
                granted=(),
                explanation="subject no longer exists",
            )
        decision = self.roles.decide(roles, required)
        logger.info(
            "authorize %s subject=%s required=%s matched=%s",
            "allowed" if decision.allowed else "denied",
            record.subject, required, decision.matched_grant,
        )
        return decision
