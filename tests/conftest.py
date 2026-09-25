"""共享夹具：受控时钟、预置服务，以及审计日志辅助。

每个用例通过 audit(...) 打印：请求输入、命中的判定依据、最终结论，
并在结束时校验日志中从未出现明文凭证或口令。
"""
from __future__ import annotations

import logging

import pytest

from app.config import Settings
from app.service import AuthService

logger = logging.getLogger("test.audit")


def audit(action: str, request_input: str, basis: str, conclusion: str) -> None:
    """统一审计行：输入 / 依据 / 结论。敏感值只允许传指纹，禁止传明文。"""
    logger.info(
        "AUDIT action=%s | input=%s | basis=%s | conclusion=%s",
        action, request_input, basis, conclusion,
    )


@pytest.fixture
def settings() -> Settings:
    return Settings(
        session_ttl_seconds=100.0,
        max_failed_attempts=3,
        lockout_seconds=30.0,
        replay_grace_seconds=1.0,
    )


@pytest.fixture
def svc(settings: Settings) -> AuthService:
    s = AuthService(settings)
    s.roles.define_role("viewer", ["documents:read"])
    s.roles.define_role("editor", ["documents:read", "documents:write"])
    s.roles.define_role("admin", ["*:*"])
    s.register_user("alice", "alice-secret", ["viewer"])
    s.register_user("bob", "bob-secret", ["editor"])
    return s


@pytest.fixture(autouse=True)
def _no_plaintext_in_logs(caplog, monkeypatch):
    """校验测试期间的所有日志不含明文凭证与口令。"""
    import app.tokens as tokens_mod

    issued_plaintexts: set[str] = set()
    original_generate = tokens_mod.generate_token

    def spy_generate(num_bytes: int) -> str:
        value = original_generate(num_bytes)
        issued_plaintexts.add(value)
        return value

    monkeypatch.setattr(tokens_mod, "generate_token", spy_generate)
    import app.session_store as store_mod
    monkeypatch.setattr(store_mod, "generate_token", spy_generate)
    yield
    text = "\n".join(
        record.getMessage() for record in caplog.records
        if record.name != "test.audit"
    )
    for secret in ("alice-secret", "bob-secret"):
        assert secret not in text, "日志中出现了明文口令"
    for plaintext in issued_plaintexts:
        assert plaintext not in text, "日志中出现了明文凭证"
