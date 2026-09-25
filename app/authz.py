"""基于角色与资源层级的权限判定（最小权限原则）。"""
from __future__ import annotations

from app.models import Permission, Role


class Authorizer:
    """按授予集合判定请求权限是否被允许。"""

    def __init__(self, roles: dict[str, Role]) -> None:
        self._roles = roles

    def grants_for(self, role_names: list[str]) -> list[Permission]:
        raise NotImplementedError

    def is_allowed(self, role_names: list[str], required: Permission) -> bool:
        """授予可覆盖请求（层级前缀或通配），但请求不得超出授予范围。"""
        raise NotImplementedError
