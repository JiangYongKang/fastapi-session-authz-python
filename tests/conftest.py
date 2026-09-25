import logging

import pytest

from app.authz import Authorizer
from app.config import Settings
from app.models import Permission, Role
from app.rate_limit import RateLimiter
from app.service import AuthService
from app.session_store import SessionStore


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def settings() -> Settings:
    return Settings(session_ttl_seconds=100.0, max_failed_attempts=3,
                    lockout_seconds=60.0, failure_window_seconds=600.0)


@pytest.fixture()
def roles() -> dict[str, Role]:
    return {
        "reader": Role("reader", [Permission("read", "docs")]),
        "editor": Role("editor", [Permission("read", "docs"),
                                  Permission("write", "docs/team-a")]),
        "admin": Role("admin", [Permission("*", "*")]),
    }


@pytest.fixture()
def service(settings, roles) -> AuthService:
    svc = AuthService(
        settings,
        SessionStore(settings.session_ttl_seconds),
        Authorizer(roles),
        RateLimiter(settings.max_failed_attempts,
                    settings.lockout_seconds,
                    settings.failure_window_seconds),
        users={"alice": "pw-alice", "bob": "pw-bob"},
    )
    svc.set_user_roles("alice", ["reader"])
    svc.set_user_roles("bob", ["editor"])
    return svc


@pytest.fixture(autouse=True)
def _verbose_logs(caplog):
    """单测日志打印请求输入、判定依据与最终结论。"""
    caplog.set_level(logging.INFO, logger="app.service")
    yield
    for record in caplog.records:
        print(f"[audit] {record.getMessage()}")
