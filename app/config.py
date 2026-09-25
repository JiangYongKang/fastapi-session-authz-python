"""配置项：凭证生命周期、限流与锁定参数。"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    session_ttl_seconds: float = 3600.0
    max_failed_attempts: int = 5
    lockout_seconds: float = 300.0
    # 失败计数窗口：超过该时长的历史失败不再计入
    failure_window_seconds: float = 600.0


DEFAULT_SETTINGS = Settings()
