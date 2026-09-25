"""认证与授权服务：组合凭证存储、权限注册表与限流器，对外提供用例级接口。"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading

from app.authz import RoleRegistry
from app.config import Settings
from app.models import AuthzDecision, IssuedToken, RefreshResult
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

    # ---- 用例 ----

    def login(
        self, source: str, username: str, password: str, now: float
    ) -> IssuedToken | None:
        """登录：限流检查 -> 校验口令 -> 签发会话。

        锁定、口令错误、用户不存在对外表现一致（均返回 None），
        日志只记录来源与指纹，绝不记录明文口令或凭证。
        """
        if self.limiter.is_locked(source, now):
            logger.warning("login rejected reason=locked source=%s", source)
            return None
        if not self._verify_password(username, password):
            triggered = self.limiter.record_failure(source, now)
            logger.warning(
                "login rejected reason=bad_credentials source=%s lockout=%s",
                source, triggered,
            )
            return None
        self.limiter.record_success(source)
        roles = self._roles_of(username) or frozenset()
        token = self.sessions.issue(username, roles, now)
        logger.info(
            "login ok subject=%s source=%s token_fp=%s",
            username, source, fingerprint(token.plaintext),
        )
        return token

    def refresh(self, plaintext: str, now: float) -> RefreshResult:
        return self.sessions.refresh(plaintext, now)

    def logout(self, plaintext: str) -> bool:
        return self.sessions.revoke(plaintext)

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
