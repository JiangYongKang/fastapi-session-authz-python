"""来源风险准入：登录失败、凭证换发、凭证注销共享同一份风险计数与锁定状态。

- 渐进锁定：同一来源连续触发锁定时，时长按倍数递增，直到可配置上限。
- 平稳恢复：连续一段时间（calm_seconds）没有新失败后，递增级别回落，
  下一次锁定重新从基础时长计起。
- 有界状态：被记录的来源数量有上限（max_sources），闲置状态自动回收；
  回收与淘汰是确定性的，且绝不提前放行仍在锁定期的来源。

并发一致性：所有计数与状态变更都在同一把锁内完成——
锁定期内不会被放行；锁定期间到达的失败如实计入但不延长当前锁定期
（locked_until 一旦设定绝不滑动）；锁定期满时若累计失败仍达阈值，
按升级后的时长开启一次“新”锁定，而不是续旧锁。
"""
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
    lockout_level: int = 0  # 已连续锁定的次数，决定下一次锁定时长
    last_failure_at: float | None = None
    last_seen: float = 0.0  # 最近一次任意访问时刻，用于闲置回收与淘汰


class RateLimiter:
    """按来源（IP/主体）统计风险失败，达到阈值即锁定，锁定时长渐进升级。"""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._sources: dict[str, _SourceState] = {}

    # ---- 内部辅助（调用方须已持有锁） ----

    def _lock_duration(self, level: int) -> float:
        s = self._settings
        return min(
            s.lockout_seconds * (s.lockout_multiplier ** level),
            s.lockout_max_seconds,
        )

    def _is_locked(self, state: _SourceState, now: float) -> bool:
        return state.locked_until is not None and now < state.locked_until

    def _reclaim_idle(self, now: float) -> int:
        """回收闲置且未锁定的来源状态。确定性：只取决于事件序列与时间戳。"""
        idle_before = now - self._settings.source_idle_seconds
        victims = [
            key
            for key, st in self._sources.items()
            if st.last_seen <= idle_before and not self._is_locked(st, now)
        ]
        for key in victims:
            del self._sources[key]
        if victims:
            logger.info("idle sources reclaimed count=%d", len(victims))
        return len(victims)

    def _evict_one(self, now: float) -> bool:
        """淘汰一个来源以腾出容量。确定性规则：

        只在未处于锁定期的来源中选择（锁定中的来源绝不被提前放行）；
        优先淘汰未决失败数最少的来源（保护最接近阈值的进行序列），
        其次按 last_seen 最旧、来源名字典序。
        """
        candidates = [
            (st.failures, st.last_seen, key)
            for key, st in self._sources.items()
            if not self._is_locked(st, now)
        ]
        if not candidates:
            return False
        _, _, victim = min(candidates)
        del self._sources[victim]
        logger.info("source state evicted source=%s reason=capacity", victim)
        return True

    def _state_for(self, source: str, now: float) -> _SourceState | None:
        """取来源状态；不存在时按容量策略创建。返回 None 表示容量已满且
        无可回收/淘汰项（全部在锁定期），本次无法为其计数。"""
        state = self._sources.get(source)
        if state is not None:
            state.last_seen = now
            return state
        if len(self._sources) >= self._settings.max_sources:
            self._reclaim_idle(now)
        if len(self._sources) >= self._settings.max_sources:
            self._evict_one(now)
        if len(self._sources) >= self._settings.max_sources:
            logger.warning(
                "source state dropped source=%s reason=capacity_exhausted", source
            )
            return None
        state = _SourceState(last_seen=now)
        self._sources[source] = state
        return state

    # ---- 对外接口 ----

    def is_locked(self, source: str, now: float) -> bool:
        """准入检查。锁定期满时惰性结算：

        - 锁定期间累计的失败仍达阈值 -> 按升级后的时长开启新锁定；
        - 否则清零计数、解除锁定，来源恢复正常。
        """
        with self._lock:
            state = self._sources.get(source)
            if state is None:
                return False
            state.last_seen = now
            if state.locked_until is None:
                return False
            if now < state.locked_until:
                return True
            if state.failures >= self._settings.max_failed_attempts:
                # 锁定期间仍在持续失败：期满即按下一级时长重新锁定
                duration = self._lock_duration(state.lockout_level)
                state.locked_until = now + duration
                state.lockout_level += 1
                state.failures = 0
                logger.warning(
                    "source re-locked source=%s level=%d duration=%.3f",
                    source, state.lockout_level, duration,
                )
                return True
            state.locked_until = None
            state.failures = 0
            logger.info("lockout expired source=%s", source)
            return False

    def record_failure(self, source: str, now: float) -> bool:
        """记录一次失败，返回本次是否触发了（新）锁定。

        锁定期间到达的失败如实计入计数，但不改变 locked_until、
        不触发新锁定——当前锁定期不会被延长。
        """
        with self._lock:
            state = self._state_for(source, now)
            if state is None:
                return False  # 容量被锁定中的来源占满：放行但不计数（有界降级）
            if (
                state.last_failure_at is not None
                and not self._is_locked(state, now)
                and now - state.last_failure_at >= self._settings.calm_seconds
            ):
                # 平稳期已过：递增级别与计数回落，从基础时长重新计起
                state.lockout_level = 0
                state.failures = 0
                logger.info("calm period elapsed source=%s level reset", source)
            state.failures += 1
            state.last_failure_at = now
            if self._is_locked(state, now):
                logger.info(
                    "failure recorded while locked source=%s pending=%d",
                    source, state.failures,
                )
                return False
            if state.failures >= self._settings.max_failed_attempts:
                duration = self._lock_duration(state.lockout_level)
                state.locked_until = now + duration
                state.lockout_level += 1
                state.failures = 0  # 锁定期间重新累计，期满后统一结算
                logger.warning(
                    "source locked source=%s level=%d duration=%.3f until=%.3f",
                    source, state.lockout_level, duration, state.locked_until,
                )
                return True
            logger.info(
                "failure recorded source=%s count=%d", source, state.failures
            )
            return False

    def record_success(self, source: str, now: float) -> None:
        """一次正常操作成功：清零失败计数（不影响递增级别与锁定状态）。"""
        with self._lock:
            state = self._sources.get(source)
            if state is not None:
                state.last_seen = now
                state.failures = 0

    def locked_until(self, source: str) -> float | None:
        with self._lock:
            state = self._sources.get(source)
            return state.locked_until if state else None

    def tracked_sources(self) -> int:
        """当前被记录的来源数量（测试与运维观测用）。"""
        with self._lock:
            return len(self._sources)
