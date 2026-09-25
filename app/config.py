"""配置项：凭证生命周期、限流与锁定参数。"""
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


DEFAULT_SETTINGS = Settings()
