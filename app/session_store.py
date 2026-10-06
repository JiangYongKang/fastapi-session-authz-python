"""会话凭证存储：签发、轮换、撤销、校验。并发下保证轮换只成功一次。"""
from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import replace

from app.config import Settings
from app.models import (
    IssuedToken,
    RefreshResult,
    RejectReason,
    SessionRecord,
    SessionStatus,
)
from app.tokens import fingerprint, generate_token, hash_token

logger = logging.getLogger("authz.session")


class SessionStore:
    """内存会话存储。所有状态变更在同一把锁内完成，保证轮换的原子性。"""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._by_hash: dict[str, SessionRecord] = {}

    # ---- 内部辅助（调用方须已持有锁） ----

    def _new_record(
        self, subject: str, roles: frozenset[str], now: float, family_id: str
    ) -> IssuedToken:
        plaintext = generate_token(self._settings.token_bytes)
        record = SessionRecord(
            token_hash=hash_token(plaintext),
            subject=subject,
            roles=roles,
            issued_at=now,
            expires_at=now + self._settings.session_ttl_seconds,
            status=SessionStatus.ACTIVE,
            family_id=family_id,
        )
        self._by_hash[record.token_hash] = record
        return IssuedToken(plaintext=plaintext, record=record)

    def _set_status(
        self, token_hash: str, status: SessionStatus, now: float | None = None
    ) -> None:
        record = self._by_hash.get(token_hash)
        if record is not None:
            rotated_at = now if status == SessionStatus.ROTATED else record.rotated_at
            self._by_hash[token_hash] = replace(
                record, status=status, rotated_at=rotated_at
            )

    def _revoke_family_locked(self, family_id: str) -> int:
        count = 0
        for h, rec in list(self._by_hash.items()):
            if rec.family_id == family_id and rec.status != SessionStatus.REVOKED:
                self._by_hash[h] = replace(rec, status=SessionStatus.REVOKED)
                count += 1
        return count

    # ---- 对外接口 ----

    def issue(self, subject: str, roles: frozenset[str], now: float) -> IssuedToken:
        with self._lock:
            token = self._new_record(subject, roles, now, family_id=uuid.uuid4().hex)
        logger.info(
            "session issued subject=%s token_fp=%s expires_at=%.3f",
            subject, fingerprint(token.plaintext), token.record.expires_at,
        )
        return token

    def validate(self, plaintext: str, now: float) -> SessionRecord | None:
        """校验凭证：仅 ACTIVE 且未过期时返回记录，否则返回 None。"""
        with self._lock:
            record = self._by_hash.get(hash_token(plaintext))
            if (
                record is not None
                and record.status == SessionStatus.ACTIVE
                and record.expires_at > now
            ):
                return record
            return None

    def classify(self, plaintext: str, now: float) -> RejectReason | None:
        """区分拒绝原因：有效返回 None，否则返回 过期/已撤销/被重放/未知。"""
        with self._lock:
            record = self._by_hash.get(hash_token(plaintext))
            if record is None:
                return RejectReason.UNKNOWN
            if record.status == SessionStatus.REVOKED:
                return RejectReason.REVOKED
            if record.status == SessionStatus.ROTATED:
                return RejectReason.REPLAYED
            if record.expires_at <= now:
                return RejectReason.EXPIRED
            return None

    def refresh(self, plaintext: str, now: float) -> RefreshResult:
        """轮换：旧凭证原子作废并签发新凭证。

        整个“检查旧凭证 + 作废 + 签发新凭证”在同一把锁内完成，
        并发到达的刷新请求只有一个能成功，其余按重放拒绝。
        检测到重放（已轮换的凭证再次被使用）时，撤销整条轮换链。
        """
        with self._lock:
            record = self._by_hash.get(hash_token(plaintext))
            fp = fingerprint(plaintext)
            if record is None:
                logger.warning("refresh rejected reason=unknown token_fp=%s", fp)
                return RefreshResult(ok=False, reason=RejectReason.UNKNOWN)
            if record.status == SessionStatus.REVOKED:
                logger.warning("refresh rejected reason=revoked token_fp=%s", fp)
                return RefreshResult(ok=False, reason=RejectReason.REVOKED)
            if record.status == SessionStatus.ROTATED:
                assert record.rotated_at is not None
                if now - record.rotated_at <= self._settings.replay_grace_seconds:
                    # 宽限窗口内：并发竞争的重复使用，拒绝并保留胜出的新链；
                    # 标记 racing=True，调用方不将其计入来源风险
                    logger.warning(
                        "refresh rejected reason=replayed token_fp=%s mode=racing", fp
                    )
                    return RefreshResult(
                        ok=False, reason=RejectReason.REPLAYED, racing=True
                    )
                # 窗口之外：旧凭证事后被重放，疑似被盗，撤销整条链
                revoked = self._revoke_family_locked(record.family_id)
                logger.warning(
                    "refresh rejected reason=replayed token_fp=%s "
                    "mode=stolen family_revoked=%d",
                    fp, revoked,
                )
                return RefreshResult(ok=False, reason=RejectReason.REPLAYED)
            if record.expires_at <= now:
                logger.warning("refresh rejected reason=expired token_fp=%s", fp)
                return RefreshResult(ok=False, reason=RejectReason.EXPIRED)

            self._set_status(record.token_hash, SessionStatus.ROTATED, now=now)
            token = self._new_record(
                record.subject, record.roles, now, family_id=record.family_id
            )
            logger.info(
                "session rotated subject=%s old_fp=%s new_fp=%s",
                record.subject, fp, fingerprint(token.plaintext),
            )
            return RefreshResult(ok=True, token=token)

    def revoke(self, plaintext: str) -> bool:
        with self._lock:
            record = self._by_hash.get(hash_token(plaintext))
            if record is None or record.status == SessionStatus.REVOKED:
                return False
            self._set_status(record.token_hash, SessionStatus.REVOKED)
        logger.info("session revoked token_fp=%s", fingerprint(plaintext))
        return True

    def revoke_subject(self, subject: str) -> int:
        """撤销某主体的全部会话（权限变更时调用，立即生效）。"""
        with self._lock:
            count = 0
            for h, rec in list(self._by_hash.items()):
                if rec.subject == subject and rec.status != SessionStatus.REVOKED:
                    self._by_hash[h] = replace(rec, status=SessionStatus.REVOKED)
                    count += 1
        logger.info("subject sessions revoked subject=%s count=%d", subject, count)
        return count
