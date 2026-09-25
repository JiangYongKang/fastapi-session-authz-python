"""权限判定：层级前缀、通配授予、越权放大拒绝、变更立即生效。"""
import pytest

from app.models import Permission
from app.service import AuthError


def test_prefix_grant_covers_subresource(service, clock):
    token = service.login("alice", "pw-alice", "ip-a", clock())
    assert service.authorize(token, Permission("read", "docs/a/b"), clock()) == "alice"


def test_narrow_grant_cannot_escalate(service, clock):
    """bob 仅持有 docs/team-a 的写权限，不得放大到父级或其他分支。"""
    token = service.login("bob", "pw-bob", "ip-b", clock())
    assert service.authorize(token, Permission("write", "docs/team-a/x"), clock()) == "bob"
    for required in (
        Permission("write", "docs"),            # 向父级放大
        Permission("write", "docs/team-b"),     # 横向越权
        Permission("delete", "docs/team-a/x"),  # 动作越权
    ):
        with pytest.raises(AuthError) as exc:
            service.authorize(token, required, clock())
        assert exc.value.code == "forbidden"


def test_wildcard_grant_covers_everything(service, clock):
    service.set_user_roles("alice", ["admin"])
    token = service.login("alice", "pw-alice", "ip-c", clock())
    assert service.authorize(token, Permission("delete", "any/thing"), clock()) == "alice"


def test_request_wildcard_cannot_escalate(service, clock):
    """请求侧携带通配符不得套取更大范围。"""
    token = service.login("alice", "pw-alice", "ip-d", clock())
    with pytest.raises(AuthError) as exc:
        service.authorize(token, Permission("*", "docs"), clock())
    assert exc.value.code == "forbidden"


def test_permission_change_effective_immediately(service, clock, roles):
    """角色定义变更后，已签发的凭证在后续请求中立即按新规则判定。"""
    token = service.login("alice", "pw-alice", "ip-e", clock())
    with pytest.raises(AuthError):
        service.authorize(token, Permission("write", "docs/x"), clock())
    roles["reader"].grants.append(Permission("write", "docs"))
    assert service.authorize(token, Permission("write", "docs/x"), clock()) == "alice"
    roles["reader"].grants.clear()
    roles["reader"].grants.append(Permission("read", "docs"))
    with pytest.raises(AuthError):
        service.authorize(token, Permission("write", "docs/x"), clock())


def test_role_reassignment_effective_immediately(service, clock):
    """角色成员关系变更立即生效，不缓存旧结论。"""
    token = service.login("alice", "pw-alice", "ip-f", clock())
    service.set_user_roles("alice", ["editor"])
    assert service.authorize(token, Permission("write", "docs/team-a/f"), clock()) == "alice"
    service.set_user_roles("alice", [])
    with pytest.raises(AuthError):
        service.authorize(token, Permission("read", "docs/x"), clock())


def test_revoked_session_not_served_from_cache(service, clock):
    """先放行、再撤销、后必须拒绝：不得因缓存继续放行。"""
    token = service.login("alice", "pw-alice", "ip-g", clock())
    service.authorize(token, Permission("read", "docs/x"), clock())
    service.logout(token)
    with pytest.raises(AuthError) as exc:
        service.authorize(token, Permission("read", "docs/x"), clock())
    assert exc.value.code == "session_revoked"
