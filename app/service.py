"""认证与授权编排：登录、刷新、访问判定，统一限流与审计日志。

安全约定：
- 日志只记录请求输入的非敏感部分（用户名、来源、权限、判定依据与结论），
  凭证一律以 SHA-256 指纹前缀出现，绝不记录明文口令或完整令牌。
- 登录失败对外统一为 invalid_credentials，不区分“用户不存在”与“口令错误”。
- 权限判定实时读取角色表与角色成员关系，不做缓存：
  权限变更或凭证撤销在后续请求中立即生效。
"""
from __future__ import annotations

import hashlib
import hmac
import logging

from app.authz import Authorizer
from app.config import Settings
from app.models import Permission, RejectReason
from app.rate_limit import RateLimiter
from app.session_store import RefreshRejected, SessionStore

logger = logging.getLogger("app.service")


class AuthError(Exception):
    """对外统一的认证/授权失败，code 可区分，message 不泄露内部细节。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_REASON_TO_CODE = {
    RejectReason.EXPIRED: "session_expired",
    RejectReason.REVOKED: "session_revoked",
    RejectReason.REPLAYED: "session_replayed",
    RejectReason.UNKNOWN: "session_invalid",
}


def _fingerprint(token_id: str) -> str:
    return hashlib.sha256(token_id.encode()).hexdigest()[:12]


class AuthService:
    def __init__(self, settings: Settings, store: SessionStore,
                 authorizer: Authorizer, limiter: RateLimiter,
                 users: dict[str, str]) -> None:
        self._settings = settings
        self._store = store
        self._authorizer = authorizer
        self._limiter = limiter
        self._users = users  # username -> password（演示用内存表）
        self._user_roles: dict[str, list[str]] = {}

    def set_user_roles(self, username: str, roles: list[str]) -> None:
        self._user_roles[username] = list(roles)

    def _check_rate_limit(self, source: str, now: float, action: str) -> None:
        verdict = self._limiter.check(source, now)
        if not verdict.allowed:
            logger.info(
                "action=%s source=%s verdict=rate_limited locked_until=%s",
                action, source, verdict.locked_until,
            )
            raise AuthError("rate_limited", "too many failed attempts, try later")

    def login(self, username: str, password: str, source: str, now: float) -> str:
        self._check_rate_limit(source, now, "login")
        expected = self._users.get(username)
        # 用户不存在时用哑值参与比较，避免时间侧信道区分用户是否存在。
        candidate = expected if expected is not None else "x" * len(password)
        if expected is None or not hmac.compare_digest(candidate, password):
            verdict = self._limiter.record_failure(source, now)
            logger.info(
                "action=login source=%s username=%s verdict=deny "
                "reason=invalid_credentials failures=%d",
                source, username, verdict.failure_count,
            )
            raise AuthError("invalid_credentials", "invalid username or password")
        self._limiter.record_success(source)
        roles = self._user_roles.get(username, [])
        record = self._store.issue(username, roles, now)
        logger.info(
            "action=login source=%s username=%s roles=%s verdict=allow token=%s",
            source, username, roles, _fingerprint(record.token_id),
        )
        return record.token_id

    def refresh(self, token_id: str, source: str, now: float) -> str:
        self._check_rate_limit(source, now, "refresh")
        fp = _fingerprint(token_id)
        try:
            record = self._store.refresh(token_id, now)
        except RefreshRejected as exc:
            self._limiter.record_failure(source, now)
            logger.info(
                "action=refresh source=%s token=%s verdict=deny reason=%s",
                source, fp, exc.reason.value,
            )
            raise AuthError(_REASON_TO_CODE[exc.reason],
                            f"session rejected: {exc.reason.value}") from exc
        logger.info(
            "action=refresh source=%s token=%s verdict=allow new_token=%s",
            source, fp, _fingerprint(record.token_id),
        )
        return record.token_id

    def logout(self, token_id: str) -> None:
        self._store.revoke(token_id)
        logger.info("action=logout token=%s verdict=revoked",
                    _fingerprint(token_id))

    def authorize(self, token_id: str, required: Permission, now: float) -> str:
        """校验凭证并判定权限，返回主体名；失败抛 AuthError。"""
        fp = _fingerprint(token_id)
        try:
            record = self._store.validate(token_id, now)
        except RefreshRejected as exc:
            logger.info(
                "action=authorize token=%s required=%s verdict=deny reason=%s",
                fp, required, exc.reason.value,
            )
            raise AuthError(_REASON_TO_CODE[exc.reason],
                            f"session rejected: {exc.reason.value}") from exc
        # 实时解析角色成员关系与角色定义，权限变更立即生效。
        roles = self._user_roles.get(record.subject, [])
        grants = self._authorizer.grants_for(roles)
        allowed = self._authorizer.is_allowed(roles, required)
        logger.info(
            "action=authorize token=%s subject=%s required=%s grants=%s "
            "verdict=%s",
            fp, record.subject, required, [str(g) for g in grants],
            "allow" if allowed else "deny",
        )
        if not allowed:
            raise AuthError("forbidden", "insufficient permissions")
        return record.subject
