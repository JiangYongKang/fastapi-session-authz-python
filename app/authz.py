"""权限判定：角色 -> 权限授予，支持资源层级与通配，按最小权限比对。

权限串格式：``resource:action``
- resource 以 ``/`` 分层，如 ``documents/reports``
- 授予中某一段为 ``*`` 时匹配该层任意单段
- 授予是所需资源的前缀时按层级向下继承（父级授予覆盖子资源）
- 授予段数多于所需资源时不覆盖（禁止向上越权放大）
- action 为 ``*`` 时匹配任意动作
判定不缓存结论，角色变更立即生效。
"""
from __future__ import annotations

import threading

from app.models import AuthzDecision


def parse_permission(perm: str) -> tuple[str, str]:
    """把 'resource:action' 拆成 (resource, action)。"""
    resource, sep, action = perm.partition(":")
    if not sep or not resource or not action:
        raise ValueError(f"invalid permission: {perm!r}")
    return resource, action


def grant_covers(grant: str, required: str) -> bool:
    """判断一条授予是否覆盖所需权限（层级前缀与通配，不得越权放大）。"""
    g_res, g_act = parse_permission(grant)
    r_res, r_act = parse_permission(required)
    if g_act != "*" and g_act != r_act:
        return False
    g_segs = g_res.split("/")
    r_segs = r_res.split("/")
    if len(g_segs) > len(r_segs):
        # 授予比所需更具体，不能向上放大
        return False
    return all(g == "*" or g == r for g, r in zip(g_segs, r_segs))


class RoleRegistry:
    """角色与权限授予的注册表，判定时不缓存结论，变更立即生效。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._roles: dict[str, tuple[str, ...]] = {}

    def define_role(self, role: str, grants: list[str]) -> None:
        for g in grants:
            parse_permission(g)  # 提前校验格式
        with self._lock:
            self._roles[role] = tuple(grants)

    def grants_for(self, roles: frozenset[str]) -> tuple[str, ...]:
        with self._lock:
            result: list[str] = []
            for role in sorted(roles):
                result.extend(self._roles.get(role, ()))
            return tuple(result)

    def decide(self, roles: frozenset[str], required: str) -> AuthzDecision:
        """返回 AuthzDecision，含命中的授予与解释。"""
        parse_permission(required)
        grants = self.grants_for(roles)
        for grant in grants:
            if grant_covers(grant, required):
                return AuthzDecision(
                    allowed=True,
                    required=required,
                    granted=grants,
                    matched_grant=grant,
                    explanation=f"grant {grant!r} covers required {required!r}",
                )
        return AuthzDecision(
            allowed=False,
            required=required,
            granted=grants,
            matched_grant=None,
            explanation=f"no grant covers required {required!r}",
        )
