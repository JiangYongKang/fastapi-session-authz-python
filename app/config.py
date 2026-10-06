"""配置项：凭证生命周期、来源风险准入（限流/渐进锁定/状态容量）参数。"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    session_ttl_seconds: float = 3600.0
    max_failed_attempts: int = 5
    lockout_seconds: float = 300.0
    token_bytes: int = 32
    # 轮换完成后该宽限窗口内的旧凭证重放视为并发竞争：拒绝但不吊销新链；
    # 窗口之外的重放视为凭证被盗，撤销整条轮换链
    replay_grace_seconds: float = 1.0
    # ---- 来源风险准入：渐进锁定与平稳恢复 ----
    # 连续第 n 次锁定的时长 = min(lockout_seconds * lockout_multiplier ** n,
    # lockout_max_seconds)；平静期（无新失败）后回落到基础时长重新计数
    lockout_multiplier: float = 2.0
    lockout_max_seconds: float = 3600.0
    calm_seconds: float = 900.0
    # ---- 来源风险准入：有界状态管理 ----
    # 被记录风险的来源数量上限；超出时按确定性规则回收/淘汰
    max_sources: int = 10_000
    # 来源超过该时长无任何活动且未处于锁定期，其状态可被回收
    source_idle_seconds: float = 3600.0


DEFAULT_SETTINGS = Settings()
