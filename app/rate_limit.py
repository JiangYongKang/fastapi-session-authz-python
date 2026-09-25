"""登录失败与敏感操作的限流与锁定。

规则：
- 按来源键（如 IP 或 IP+账号）统计失败窗口内的连续失败次数。
- 达到阈值即锁定 lockout_seconds，锁定期间一律拒绝（含本可能成功的请求）。
- 锁定期满后状态自动清零恢复；成功一次也会清零计数。
- 计数与锁定判定在同一把锁内完成：并发失败各自恰好计数一次，
  不会漏计绕过阈值，也不会重复计数。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitVerdict:
    allowed: bool
    locked_until: float | None
    failure_count: int


@dataclass
class _Entry:
    failures: list[float]
    locked_until: float | None = None


class RateLimiter:
    """按来源键计数连续失败，达到阈值后锁定一段时间。"""

    def __init__(self, max_failed_attempts: int, lockout_seconds: float,
                 failure_window_seconds: float) -> None:
        self._max = max_failed_attempts
        self._lockout = lockout_seconds
        self._window = failure_window_seconds
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    def _prune(self, entry: _Entry, now: float) -> None:
        """锁内：清理窗口外失败记录，并处理锁定期满恢复。"""
        if entry.locked_until is not None and now >= entry.locked_until:
            entry.locked_until = None
            entry.failures.clear()
        cutoff = now - self._window
        entry.failures = [t for t in entry.failures if t > cutoff]

    def _verdict(self, entry: _Entry) -> RateLimitVerdict:
        return RateLimitVerdict(
            allowed=entry.locked_until is None,
            locked_until=entry.locked_until,
            failure_count=len(entry.failures),
        )

    def check(self, key: str, now: float) -> RateLimitVerdict:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return RateLimitVerdict(True, None, 0)
            self._prune(entry, now)
            return self._verdict(entry)

    def record_failure(self, key: str, now: float) -> RateLimitVerdict:
        with self._lock:
            entry = self._entries.setdefault(key, _Entry(failures=[]))
            self._prune(entry, now)
            if entry.locked_until is not None:
                # 锁定期内的失败不再重复计数，仅维持锁定。
                return self._verdict(entry)
            entry.failures.append(now)
            if len(entry.failures) >= self._max:
                entry.locked_until = now + self._lockout
            return self._verdict(entry)

    def record_success(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)
