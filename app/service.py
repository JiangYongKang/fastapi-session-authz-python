"""认证与授权编排：登录、刷新、访问判定，统一限流与审计日志。"""
from __future__ import annotations

import logging

from app.authz import Authorizer
from app.config import Settings
from app.models import Permission
from app.rate_limit import RateLimiter
from app.session_store import SessionStore

logger = logging.getLogger("app.service")


class AuthError(Exception):
    """对外统一的认证/授权失败，不泄露内部细节。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class AuthService:
    def __init__(self, settings: Settings, store: SessionStore,
                 authorizer: Authorizer, limiter: RateLimiter,
                 users: dict[str, str]) -> None:
        self._settings = settings
        self._store = store
        self._authorizer = authorizer
        self._limiter = limiter
        self._users = users  # username -> password（演示用内存表）
        self._user_roles: dict[str, list[str]] = {}

    def set_user_roles(self, username: str, roles: list[str]) -> None:
        self._user_roles[username] = list(roles)

    def login(self, username: str, password: str, source: str, now: float) -> str:
        raise NotImplementedError

    def refresh(self, token_id: str, source: str, now: float) -> str:
        raise NotImplementedError

    def logout(self, token_id: str) -> None:
        raise NotImplementedError

    def authorize(self, token_id: str, required: Permission, now: float) -> str:
        """校验凭证并判定权限，返回主体名；失败抛 AuthError。"""
        raise NotImplementedError
