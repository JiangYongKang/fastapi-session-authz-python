"""统一的来源风险准入：登录失败、凭证换发、凭证注销共享同一份风险计数与锁定。

- 敏感操作（登录 / 换发 / 注销）必须先经 ``gate`` 准入：来源处于锁定期内
  一律拒绝，且拒绝发生在触碰任何凭证状态之前——不会产生新凭证，也不会
  改动现有凭证。
- 同一来源的敏感操作经**条带锁**串行化，准入判定、失败计入与凭证变更
  落在同一个串行区间内：锁定期内不会有请求被放行，刚清零的计数也不会
  被旧请求写回，锁定期不会被反复续上。
- **渐进式锁定**：同一来源连续触发锁定时，锁定时长按倍数递增直至上限；
  平稳期内没有新失败后，等级回到基础档重新计数。
- **有界状态**：被记录的来源数量有上限；闲置来源（计数为零、未锁定、
  已过平稳期）被确定性回收；仍在锁定期或正在累计失败的来源不会被回收。

日志只记录来源、计数与等级，绝不记录凭证或口令。
"""
from __future__ import annotations

import contextlib
import logging
import threading
import time
import zlib
from collections.abc import Iterator
from dataclasses import dataclass

from app.config import Settings

logger = logging.getLogger("authz.ratelimit")

# 来源串行化条带数：固定常量，来源按 crc32 稳定映射，行为可复现
_NUM_STRIPES = 64


@dataclass
class _SourceState:
    failures: int = 0
    locked_until: float | None = None
    level: int = 0  # 已连续触发的锁定次数：决定下一档锁定时长
    last_failure_at: float | None = None  # 最近一次失败：失败序列老化判断
    last_lock_at: float | None = None  # 最近一次锁定的期满时刻：平稳期起算
    in_gate: bool = False  # 正有敏感操作在准入区间内：禁止回收


@dataclass(frozen=True)
class SourceSnapshot:
    """来源风险状态的只读快照（供测试与日志使用）。"""

    failures: int
    locked_until: float | None
    level: int
    last_failure_at: float | None
    last_lock_at: float | None = None


class HeldGate:
    """``RateLimiter.gate`` 持有的准入句柄。

    调用方在句柄有效期内持有该来源的条带锁；业务结论必须且只能回报一次：
    敏感操作失败调 ``report_failure``，成功调 ``report_success``。
    """

    def __init__(
        self, limiter: RateLimiter, source: str, stripe: threading.Lock
    ) -> None:
        self._limiter = limiter
        self._source = source
        self._stripe = stripe
        self.admitted = False
        self.locked_until: float | None = None

    def report_failure(self, now: float) -> bool:
        """计入一次失败（共享风险计数），返回本次是否触发了锁定。"""
        return self._limiter._report_failure_held(self._source, now)

    def report_success(self) -> None:
        """回报成功：清零当前失败计数。"""
        self._limiter._report_success_held(self._source)

    def _release(self) -> None:
        self._limiter._leave_gate(self._source)
        self._stripe.release()


class RateLimiter:
    """按来源统计敏感操作失败，阈值触发渐进式锁定，状态有界回收。

    锁序恒为「条带锁 -> 内部锁」，回收只在内部锁内进行、不获取条带锁，
    因此不存在死锁；被回收候选若正处于准入区间（``in_gate``）则保留，
    不会清掉正在累计的序列。
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._sources: dict[str, _SourceState] = {}
        self._stripes = tuple(threading.Lock() for _ in range(_NUM_STRIPES))

    # ---- 条带与纯判定（内部锁内） ----

    def _stripe_for(self, source: str) -> threading.Lock:
        idx = zlib.crc32(source.encode("utf-8")) % _NUM_STRIPES
        return self._stripes[idx]

    def _next_duration(self, state: _SourceState) -> float:
        """第 level+1 档锁定时长：基础 * 倍数^level，封顶为上限。"""
        scaled = self._settings.lockout_seconds * (
            self._settings.lockout_multiplier ** state.level
        )
        return min(self._settings.max_lockout_seconds, scaled)

    def _expire_and_calm(self, state: _SourceState, source: str, now: float) -> None:
        """锁定期满解除并清零计数；未锁定且超过平稳期时等级回到基础档。

        锁定期内（未到期）绝不动计数与等级，避免正在生效的锁定被提前清零。
        """
        if state.locked_until is not None:
            if now < state.locked_until:
                return
            state.locked_until = None
            state.failures = 0
            logger.info("lockout expired source=%s", source)
        if (
            state.level > 0
            and state.last_lock_at is not None
            and now - state.last_lock_at >= self._settings.calm_seconds
        ):
            state.level = 0
            logger.info("risk level reset source=%s reason=calm", source)

    def _is_idle(self, state: _SourceState, now: float) -> bool:
        """判定一个来源状态是否可回收：确定性，且绝不提前放行/清零活跃状态。"""
        if state.in_gate:
            return False
        if state.locked_until is not None:
            return False  # 仍在锁定期（过期锁定会在准入时先解除）
        if state.failures != 0:
            return False  # 正在累计失败序列
        # 连续锁定等级仍在平稳窗口内则保留
        return not (
            state.level > 0
            and (
                state.last_lock_at is None
                or now - state.last_lock_at < self._settings.calm_seconds
            )
        )

    def _reap_idle(self, now: float) -> int:
        """回收全部闲置来源。键排序后删除，结果确定可复现。"""
        victims = [
            s for s in sorted(self._sources) if self._is_idle(self._sources[s], now)
        ]
        for s in victims:
            del self._sources[s]
        if victims:
            logger.info("idle sources reaped count=%d", len(victims))
        return len(victims)

    def _ensure_capacity(self, source: str, now: float) -> bool:
        """为新来源腾出容量：先回收闲置；仍满则保安全拒绝登记。"""
        if len(self._sources) < self._settings.max_tracked_sources:
            return True
        self._reap_idle(now)
        if len(self._sources) < self._settings.max_tracked_sources:
            return True
        logger.warning(
            "risk table full source=%s tracked=%d failure_not_counted",
            source, len(self._sources),
        )
        return False

    def _bump(self, state: _SourceState, source: str, now: float) -> bool:
        """失败计数 +1 并在达阈值时进入下一档锁定（调用方持内部锁）。"""
        state.failures += 1
        state.last_failure_at = now
        if state.failures >= self._settings.max_failed_attempts:
            duration = self._next_duration(state)
            state.locked_until = now + duration
            state.level += 1
            state.last_lock_at = state.locked_until  # 期满时刻为平稳期起点
            state.failures = 0
            logger.warning(
                "source locked source=%s level=%d duration=%.3f until=%.3f",
                source, state.level, duration, state.locked_until,
            )
            return True
        logger.info(
            "failure recorded source=%s count=%d level=%d",
            source, state.failures, state.level,
        )
        return False

    # ---- 准入区间 ----

    @contextlib.contextmanager
    def gate(self, source: str, now: float) -> Iterator[HeldGate]:
        """进入来源敏感操作的准入区间。

        进入即持有该来源的条带锁，同来源的敏感操作彼此串行；退出时统一
        释放。调用方先看 ``held.admitted``：为 False 必须直接拒绝，不得
        触碰凭证；为 True 时执行业务并回报失败/成功。
        """
        stripe = self._stripe_for(source)
        stripe.acquire()
        held = HeldGate(self, source, stripe)
        try:
            with self._lock:
                self._reap_idle(now)
                state = self._sources.get(source)
                if state is not None:
                    self._expire_and_calm(state, source, now)
                    state.in_gate = True
                    held.admitted = state.locked_until is None
                    held.locked_until = state.locked_until
                else:
                    # 占位标记：本次区间内即便其它条带触发回收也不会误删本来源
                    state = _SourceState(in_gate=True)
                    self._sources[source] = state
                    held.admitted = True
            if not held.admitted:
                logger.warning(
                    "sensitive op rejected reason=rate_limited source=%s until=%.3f",
                    source, held.locked_until if held.locked_until else 0.0,
                )
            yield held
        finally:
            held._release()

    def _report_failure_held(self, source: str, now: float) -> bool:
        with self._lock:
            state = self._sources.get(source)
            if state is None:
                if not self._ensure_capacity(source, now):
                    return False
                state = _SourceState(in_gate=True)
                self._sources[source] = state
            return self._bump(state, source, now)

    def _report_success_held(self, source: str) -> None:
        with self._lock:
            state = self._sources.get(source)
            if state is not None:
                state.failures = 0

    def _leave_gate(self, source: str) -> None:
        with self._lock:
            state = self._sources.get(source)
            if state is None:
                return
            state.in_gate = False
            # 区间结束后仍是空占位（无失败/锁定/升级）：直接移除，不留空条目
            if (
                state.failures == 0
                and state.locked_until is None
                and state.level == 0
            ):
                del self._sources[source]

    # ---- 直接接口（登录之外的调用方与既有测试使用） ----

    def is_locked(self, source: str, now: float) -> bool:
        """查询锁定状态；顺带处理期满解除、平稳回落与闲置回收。"""
        stripe = self._stripe_for(source)
        stripe.acquire()
        try:
            with self._lock:
                self._reap_idle(now)
                state = self._sources.get(source)
                if state is None:
                    return False
                self._expire_and_calm(state, source, now)
                return state.locked_until is not None
        finally:
            stripe.release()

    def record_failure(self, source: str, now: float) -> bool:
        """不计入具体业务区间的失败登记（与 gate 内失败共用同一份计数）。"""
        stripe = self._stripe_for(source)
        stripe.acquire()
        try:
            with self._lock:
                self._reap_idle(now)
                state = self._sources.get(source)
                if state is not None:
                    self._expire_and_calm(state, source, now)
                if state is None:
                    if not self._ensure_capacity(source, now):
                        return False
                    state = _SourceState()
                    self._sources[source] = state
                return self._bump(state, source, now)
        finally:
            stripe.release()

    def record_success(self, source: str, now: float | None = None) -> None:
        """成功后清零失败计数（锁定等级保留，由平稳期决定回落）。

        计数归零且不再处于升级平稳窗口的闲置来源立即被回收。
        """
        if now is None:
            now = time.time()
        stripe = self._stripe_for(source)
        stripe.acquire()
        try:
            with self._lock:
                state = self._sources.get(source)
                if state is not None:
                    state.failures = 0
                    if self._is_idle(state, now):
                        del self._sources[source]
        finally:
            stripe.release()

    def locked_until(self, source: str) -> float | None:
        with self._lock:
            state = self._sources.get(source)
            return state.locked_until if state else None

    def snapshot(self, source: str) -> SourceSnapshot | None:
        with self._lock:
            state = self._sources.get(source)
            if state is None:
                return None
            return SourceSnapshot(
                failures=state.failures,
                locked_until=state.locked_until,
                level=state.level,
                last_failure_at=state.last_failure_at,
                last_lock_at=state.last_lock_at,
            )

    def tracked_count(self) -> int:
        with self._lock:
            return len(self._sources)
