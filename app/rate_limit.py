"""登录失败与敏感操作的限流与锁定：按来源计数，阈值触发锁定，期满恢复。"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

from app.config import Settings

logger = logging.getLogger("authz.ratelimit")


@dataclass
class _SourceState:
    failures: int = 0
    locked_until: float | None = None


class RateLimiter:
    """按来源（IP/主体）统计连续失败，达到阈值即锁定一段时间。

    所有计数变更在同一把锁内完成：并发请求要么全部计入、
    要么被锁定拒绝，不会漏计也不会重复计数。
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._sources: dict[str, _SourceState] = {}

    def _state(self, source: str) -> _SourceState:
        return self._sources.setdefault(source, _SourceState())

    def is_locked(self, source: str, now: float) -> bool:
        with self._lock:
            state = self._sources.get(source)
            if state is None or state.locked_until is None:
                return False
            if now < state.locked_until:
                return True
            # 锁定期满：解除并清零，恢复正常计数
            state.locked_until = None
            state.failures = 0
            logger.info("lockout expired source=%s", source)
            return False

    def record_failure(self, source: str, now: float) -> bool:
        """记录一次失败，返回本次是否触发了锁定。"""
        with self._lock:
            state = self._state(source)
            state.failures += 1
            if state.failures >= self._settings.max_failed_attempts:
                state.locked_until = now + self._settings.lockout_seconds
                state.failures = 0  # 锁定期间不再累计，期满后重新计数
                logger.warning(
                    "source locked source=%s until=%.3f", source, state.locked_until
                )
                return True
            logger.info(
                "failure recorded source=%s count=%d", source, state.failures
            )
            return False

    def record_success(self, source: str) -> None:
        """成功后清零失败计数。"""
        with self._lock:
            state = self._sources.get(source)
            if state is not None:
                state.failures = 0

    def locked_until(self, source: str) -> float | None:
        with self._lock:
            state = self._sources.get(source)
            return state.locked_until if state else None
