"""核心数据模型：会话凭证、拒绝原因、权限与角色。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class RejectReason(enum.Enum):
    """凭证被拒绝的具体原因，各类必须可区分。

    RATE_LIMITED 表示“因来源限流/锁定被拒”，此时凭证尚未被检查，
    该原因本身不携带凭证是否有效的任何信息。
    """

    EXPIRED = "expired"
    REVOKED = "revoked"
    REPLAYED = "replayed"
    UNKNOWN = "unknown"
    RATE_LIMITED = "rate_limited"


class SessionStatus(enum.Enum):
    ACTIVE = "active"
    ROTATED = "rotated"   # 已被轮换（旧凭证再次使用即视为重放）
    REVOKED = "revoked"


@dataclass(frozen=True)
class SessionRecord:
    """服务端保存的会话凭证记录（仅存哈希，不存明文）。"""

    token_hash: str
    subject: str
    roles: frozenset[str]
    issued_at: float
    expires_at: float
    status: SessionStatus = SessionStatus.ACTIVE
    family_id: str = ""  # 同一轮换链的凭证共享 family_id
    rotated_at: float | None = None  # 进入 ROTATED 状态的时刻


@dataclass(frozen=True)
class IssuedToken:
    """签发结果：明文凭证只在此处出现一次，之后只存哈希。"""

    plaintext: str
    record: SessionRecord


@dataclass(frozen=True)
class RefreshResult:
    ok: bool
    token: IssuedToken | None = None
    reason: RejectReason | None = None
    # True 表示宽限窗口内的并发竞争重放（良性竞态），不计入来源风险；
    # 窗口之外的事后重放（疑似被盗）与其他失败仍计入
    racing: bool = False


@dataclass(frozen=True)
class LogoutResult:
    """注销结论：ok=False 时 reason 区分 限流拒绝 与 凭证不可注销。"""

    ok: bool
    reason: RejectReason | None = None


@dataclass(frozen=True)
class AuthzDecision:
    """权限判定结论：可解释，包含命中依据。"""

    allowed: bool
    required: str
    granted: tuple[str, ...]
    matched_grant: str | None = None
    explanation: str = ""
