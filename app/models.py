"""核心数据模型：会话凭证、拒绝原因、权限与角色。"""
from __future__ import annotations

import enum
from dataclasses import dataclass


class RejectReason(enum.Enum):
    """凭证被拒绝的具体原因，三类必须可区分。"""

    EXPIRED = "expired"
    REVOKED = "revoked"
    REPLAYED = "replayed"
    UNKNOWN = "unknown"
    RATE_LIMITED = "rate_limited"  # 来源风险准入拒绝（与凭证原因可区分）


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
    # 重放模式：racing=并发竞争（不计风险），stolen=疑似被盗（计一次失败）
    replay_mode: str | None = None


@dataclass(frozen=True)
class LogoutResult:
    """注销结论：ok 表示本次真的撤销了一张有效凭证；限流拒绝时给出原因。"""

    ok: bool
    changed: bool = False
    reason: RejectReason | None = None


@dataclass(frozen=True)
class AuthzDecision:
    """权限判定结论：可解释，包含命中依据。"""

    allowed: bool
    required: str
    granted: tuple[str, ...]
    matched_grant: str | None = None
    explanation: str = ""
