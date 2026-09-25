"""基于角色与资源层级的权限判定（最小权限原则）。

匹配规则：
- 资源按 "/" 分段组成层级路径。授予 `docs` 覆盖 `docs/a/b`（前缀授予），
  但授予 `docs/a` 不覆盖 `docs`（请求不得超出授予范围，禁止越权放大）。
- 动作与资源均支持通配符 `*`（仅允许出现在授予侧）。
- 请求侧若含 `*`，只允许与授予完全相等，不允许用通配请求套取更大范围。
- 判定时实时读取角色表，不做结果缓存：权限变更立即生效。
"""
from __future__ import annotations

from app.models import Permission, Role


def _resource_covers(grant: str, required: str) -> bool:
    """授予资源是否覆盖请求资源（段边界对齐的前缀）。"""
    if grant == "*":
        return True
    if grant == required:
        return True
    return required.startswith(grant.rstrip("/") + "/")


def _action_covers(grant: str, required: str) -> bool:
    return grant == "*" or grant == required


class Authorizer:
    """按授予集合判定请求权限是否被允许。"""

    def __init__(self, roles: dict[str, Role]) -> None:
        self._roles = roles

    def grants_for(self, role_names: list[str]) -> list[Permission]:
        grants: list[Permission] = []
        for name in role_names:
            role = self._roles.get(name)
            if role is not None:
                grants.extend(role.grants)
        return grants

    def is_allowed(self, role_names: list[str], required: Permission) -> bool:
        # 请求侧不允许使用通配符放大权限：含 * 的请求必须逐字命中授予。
        if "*" in required.action or "*" in required.resource:
            return any(
                g.action == required.action and g.resource == required.resource
                for g in self.grants_for(role_names)
            )
        return any(
            _action_covers(g.action, required.action)
            and _resource_covers(g.resource, required.resource)
            for g in self.grants_for(role_names)
        )
