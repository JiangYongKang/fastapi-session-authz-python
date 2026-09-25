"""会话凭证存储：签发、轮换（单次使用）、撤销、过期判定。

一致性约定：
- 所有状态迁移都在同一把锁内完成，轮换是“校验旧凭证 + 原子置为
  ROTATED + 签发新凭证”的单个临界区，因此并发刷新最多只有一个成功。
- 过期采用惰性判定：读取时若 now > expires_at 则迁移为 EXPIRED，
  状态一旦离开 ACTIVE 就不可逆，保证结论可解释、可重放。
"""
from __future__ import annotations

import secrets
import threading

from app.models import RejectReason, SessionRecord, SessionStatus


class RefreshRejected(Exception):
    """凭证被拒绝，携带可区分的原因（过期/已撤销/被重放/未知）。"""

    def __init__(self, reason: RejectReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


class SessionStore:
    """线程安全的内存会话存储。"""

    def __init__(self, ttl_seconds: float) -> None:
        self._ttl = ttl_seconds
        self._records: dict[str, SessionRecord] = {}
        self._lock = threading.Lock()

    def issue(self, subject: str, roles: list[str], now: float) -> SessionRecord:
        record = SessionRecord(
            token_id=secrets.token_urlsafe(24),
            subject=subject,
            roles=list(roles),
            issued_at=now,
            expires_at=now + self._ttl,
        )
        with self._lock:
            self._records[record.token_id] = record
        return record

    def _settle_expiry(self, record: SessionRecord, now: float) -> None:
        """惰性过期：仅 ACTIVE 记录会被时间推进为 EXPIRED（锁内调用）。"""
        if record.status is SessionStatus.ACTIVE and now > record.expires_at:
            record.status = SessionStatus.EXPIRED

    def _consume(self, token_id: str, now: float) -> SessionRecord:
        """锁内校验并原子消费凭证，返回处于 ACTIVE 的记录。"""
        record = self._records.get(token_id)
        if record is None:
            raise RefreshRejected(RejectReason.UNKNOWN)
        self._settle_expiry(record, now)
        if record.status is SessionStatus.EXPIRED:
            raise RefreshRejected(RejectReason.EXPIRED)
        if record.status is SessionStatus.REVOKED:
            raise RefreshRejected(RejectReason.REVOKED)
        if record.status is SessionStatus.ROTATED:
            raise RefreshRejected(RejectReason.REPLAYED)
        return record

    def refresh(self, token_id: str, now: float) -> SessionRecord:
        """轮换凭证：旧凭证仅可被成功消费一次，返回新凭证。

        整个“消费旧凭证 + 登记新凭证”在同一临界区内完成，
        并发到达的重复刷新只会得到 REPLAYED，不会产出两个生效凭证。
        """
        with self._lock:
            old = self._consume(token_id, now)
            old.status = SessionStatus.ROTATED
            new = SessionRecord(
                token_id=secrets.token_urlsafe(24),
                subject=old.subject,
                roles=list(old.roles),
                issued_at=now,
                expires_at=now + self._ttl,
            )
            self._records[new.token_id] = new
            return new

    def revoke(self, token_id: str) -> None:
        with self._lock:
            record = self._records.get(token_id)
            if record is not None and record.status is SessionStatus.ACTIVE:
                record.status = SessionStatus.REVOKED

    def validate(self, token_id: str, now: float) -> SessionRecord:
        """校验访问用凭证（不消费），拒绝时抛出 RefreshRejected。"""
        with self._lock:
            return self._consume(token_id, now)
