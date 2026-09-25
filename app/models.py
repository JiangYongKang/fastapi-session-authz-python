"""核心数据模型：会话记录、拒绝原因、角色与权限。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class RejectReason(enum.Enum):
    """凭证被拒绝的具体原因，三类必须可区分。"""

    EXPIRED = "expired"
    REVOKED = "revoked"
    REPLAYED = "replayed"
    UNKNOWN = "unknown"


class SessionStatus(enum.Enum):
    ACTIVE = "active"
    ROTATED = "rotated"   # 已被轮换消耗（再次使用即重放）
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True)
class Permission:
    """权限：动作 + 资源层级路径，如 read:docs/a/b。"""

    action: str
    resource: str

    def __str__(self) -> str:
        return f"{self.action}:{self.resource}"


@dataclass
class Role:
    """角色：一组权限授予，支持层级与通配授予。"""

    name: str
    grants: list[Permission] = field(default_factory=list)


@dataclass
class SessionRecord:
    """服务端保存的会话凭证记录。"""

    token_id: str
    subject: str
    roles: list[str]
    issued_at: float
    expires_at: float
    status: SessionStatus = SessionStatus.ACTIVE
