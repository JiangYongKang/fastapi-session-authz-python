"""会话凭证存储：签发、轮换（单次使用）、撤销、过期判定。"""
from __future__ import annotations

from app.models import RejectReason, SessionRecord


class RefreshRejected(Exception):
    """刷新被拒绝，携带可区分的原因。"""

    def __init__(self, reason: RejectReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


class SessionStore:
    """线程安全的内存会话存储。"""

    def __init__(self, ttl_seconds: float) -> None:
        self._ttl = ttl_seconds

    def issue(self, subject: str, roles: list[str], now: float) -> SessionRecord:
        raise NotImplementedError

    def refresh(self, token_id: str, now: float) -> SessionRecord:
        """轮换凭证：旧凭证仅可被成功消费一次，返回新凭证。"""
        raise NotImplementedError

    def revoke(self, token_id: str) -> None:
        raise NotImplementedError

    def validate(self, token_id: str, now: float) -> SessionRecord:
        """校验访问用凭证，拒绝时抛出 RefreshRejected。"""
        raise NotImplementedError
