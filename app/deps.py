"""FastAPI 依赖：服务单例、时间源与凭证解析。"""
from __future__ import annotations

import os
import time

from fastapi import Depends, Header, HTTPException

from app.config import Settings
from app.service import AuthService


def _settings_from_env() -> Settings:
    return Settings(
        session_ttl_seconds=float(os.getenv("SESSION_TTL_SECONDS", "3600")),
        max_failed_attempts=int(os.getenv("MAX_FAILED_ATTEMPTS", "5")),
        lockout_seconds=float(os.getenv("LOCKOUT_SECONDS", "300")),
        replay_grace_seconds=float(os.getenv("REPLAY_GRACE_SECONDS", "1")),
    )


_service: AuthService | None = None


def get_service() -> AuthService:
    """进程级服务单例（测试可调用 reset_service 重建）。"""
    global _service
    if _service is None:
        _service = AuthService(_settings_from_env())
    return _service


def reset_service() -> None:
    global _service
    _service = None


def now() -> float:
    return time.time()


def bearer_token(authorization: str = Header(default="")) -> str:
    """从 Authorization: Bearer <token> 解析凭证，缺失时拒绝。"""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="missing bearer token")
    return token


def require(permission: str):
    """构造受保护端点的依赖：校验凭证并做权限判定。"""

    def dependency(
        token: str = Depends(bearer_token),
        svc: AuthService = Depends(get_service),
    ) -> str:
        decision = svc.authorize(token, permission, now())
        if not decision.allowed:
            raise HTTPException(status_code=403, detail=decision.explanation)
        return token

    return dependency
