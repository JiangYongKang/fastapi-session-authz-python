"""权限判定：层级继承、通配、最小权限、变更与撤销立即生效。"""
from __future__ import annotations

import pytest

from app.authz import grant_covers
from app.models import RejectReason

from .conftest import audit


@pytest.mark.parametrize(
    "grant,required,expected",
    [
        ("documents:read", "documents:read", True),
        ("documents:read", "documents/reports:read", True),          # 层级向下继承
        ("documents/reports:read", "documents:read", False),          # 禁止向上放大
        ("documents/*:read", "documents/reports:read", True),         # 通配单段
        ("documents/*:read", "images/logo:read", False),              # 通配不跨前缀
        ("documents:*", "documents/reports:write", True),             # 动作通配
        ("documents:read", "documents:write", False),                 # 动作不同
        ("*:*", "anything/deep:read", True),                          # 全局管理员
    ],
)
def test_grant_covers(grant, required, expected):
    assert grant_covers(grant, required) is expected


def test_role_grants_and_decision(svc):
    d = svc.roles.decide(frozenset({"viewer"}), "documents/2026/q3:read")
    audit("decide", "required=documents/2026/q3:read role=viewer",
          f"matched={d.matched_grant}", "allowed" if d.allowed else "denied")
    assert d.allowed
    assert d.matched_grant == "documents:read"


def test_least_privilege_denial(svc):
    token = svc.login("ip-a", "alice", "alice-secret", now=0.0)
    d = svc.authorize(token.plaintext, "documents:write", now=1.0)
    audit("authorize", "subject=alice required=documents:write",
          f"grants={svc.roles.grants_for(frozenset({'viewer'}))}", "denied:no-cover")
    assert not d.allowed
    assert d.matched_grant is None


def test_admin_wildcard(svc):
    token = svc.login("ip-b", "admin-user", "x", now=0.0) is None
    svc.register_user("root", "root-pw", ["admin"])
    token = svc.login("ip-b", "root", "root-pw", now=1.0)
    assert token is not None
    d = svc.authorize(token.plaintext, "secrets/host-1/ssh:delete", now=2.0)
    assert d.allowed and d.matched_grant == "*:*"


def test_permission_change_takes_effect_immediately(svc):
    token = svc.login("ip-c", "alice", "alice-secret", now=0.0)
    assert svc.authorize(token.plaintext, "documents:read", now=1.0).allowed
    # 收紧角色（viewer -> 无角色），同一凭证下一次请求立即被拒，无缓存放行
    svc.update_user_roles("alice", [])
    decision = svc.authorize(token.plaintext, "documents:read", now=2.0)
    audit("authorize", "subject=alice after roles=[]",
          "live role lookup, no cache", "denied:no-cover")
    assert not decision.allowed
    # 再授予也立即生效
    svc.update_user_roles("alice", ["editor"])
    assert svc.authorize(token.plaintext, "documents:write", now=3.0).allowed


def test_role_definition_change_takes_effect_immediately(svc):
    token = svc.login("ip-d", "alice", "alice-secret", now=0.0)
    assert svc.authorize(token.plaintext, "documents:read", now=1.0).allowed
    svc.roles.define_role("viewer", ["images:read"])  # viewer 不再能读 documents
    decision = svc.authorize(token.plaintext, "documents:read", now=2.0)
    audit("authorize", "viewer redefined -> images:read",
          "live registry lookup", "denied:no-cover")
    assert not decision.allowed


def test_revocation_takes_effect_immediately(svc):
    token = svc.login("ip-e", "alice", "alice-secret", now=0.0)
    assert svc.authorize(token.plaintext, "documents:read", now=1.0).allowed
    svc.logout(token.plaintext)
    decision = svc.authorize(token.plaintext, "documents:read", now=2.0)
    audit("authorize", "after revoke", f"classify={RejectReason.REVOKED}",
          "denied:revoked")
    assert not decision.allowed
    assert "revoked" in decision.explanation


def test_unknown_token_generic_denial(svc, caplog):
    decision = svc.authorize("forged-token", "documents:read", now=0.0)
    assert not decision.allowed
    assert "forged-token" not in caplog.text
