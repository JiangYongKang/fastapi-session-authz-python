"""登录失败与敏感操作的限流与锁定。"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitVerdict:
    allowed: bool
    locked_until: float | None
    failure_count: int


class RateLimiter:
    """按来源键计数连续失败，达到阈值后锁定一段时间。"""

    def __init__(self, max_failed_attempts: int, lockout_seconds: float,
                 failure_window_seconds: float) -> None:
        self._max = max_failed_attempts
        self._lockout = lockout_seconds
        self._window = failure_window_seconds

    def check(self, key: str, now: float) -> RateLimitVerdict:
        raise NotImplementedError

    def record_failure(self, key: str, now: float) -> RateLimitVerdict:
        raise NotImplementedError

    def record_success(self, key: str) -> None:
        raise NotImplementedError
