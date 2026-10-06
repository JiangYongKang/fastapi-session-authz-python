"""来源风险准入：敏感操作统一准入、渐进锁定与平稳恢复、有界状态管理。"""
from __future__ import annotations

import threading

import pytest

from app.config import Settings
from app.models import RejectReason
from app.service import AuthService

from .conftest import audit


def _lock_source(svc, source: str, now: float) -> None:
    """用连续坏口令把来源打入锁定（阈值 3）。"""
    for i in range(3):
        assert svc.login(source, "alice", "wrong", now=now + i * 0.1) is None
    assert svc.limiter.is_locked(source, now=now + 0.5)


# ---- 统一准入：锁定期内敏感操作被拒且凭证状态不变 ----


def test_locked_source_refresh_rejected_and_token_untouched(svc):
    token = svc.sessions.issue("alice", frozenset({"viewer"}), now=0.0)
    _lock_source(svc, "ip-lock", now=1.0)
    audit("login x3", "source=ip-lock bad password", "failures>=3", "locked")

    result = svc.refresh("ip-lock", token.plaintext, now=2.0)
    assert not result.ok and result.reason == RejectReason.RATE_LIMITED
    assert result.token is None
    audit("refresh", "source=ip-lock locked", "admission=locked",
          "401:rate_limited, no new token")
    # 凭证状态未被改动：未轮换、未撤销，仍然有效
    assert svc.sessions.validate(token.plaintext, now=2.1) is not None
    audit("validate", "same token after rejected refresh",
          "status=active unchanged", "accepted")

    # 锁定期满后同一凭证可正常轮换
    assert not svc.limiter.is_locked("ip-lock", now=31.2)
    ok = svc.refresh("ip-lock", token.plaintext, now=31.3)
    assert ok.ok and ok.token is not None
    audit("refresh", "source=ip-lock after lock expiry",
          "lock expired, admission=open", "rotated, new token issued")


def test_locked_source_logout_rejected_and_token_untouched(svc):
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    _lock_source(svc, "ip-lock2", now=1.0)

    result = svc.logout("ip-lock2", token.plaintext, now=2.0)
    assert not result.ok and result.reason == RejectReason.RATE_LIMITED
    audit("logout", "source=ip-lock2 locked", "admission=locked",
          "rejected:rate_limited, token not revoked")
    # 注销被拒绝 => 凭证必须保持 ACTIVE
    assert svc.sessions.validate(token.plaintext, now=2.1) is not None

    # 期满恢复后第一次正常操作照常成功
    ok = svc.logout("ip-lock2", token.plaintext, now=31.5)
    assert ok.ok
    assert svc.sessions.validate(token.plaintext, now=31.6) is None
    audit("logout", "source=ip-lock2 after lock expiry",
          "lock expired, admission=open", "revoked")


def test_risk_counter_shared_across_login_refresh_logout(svc):
    """登录失败、换发失败、注销失败共享同一份计数：三类各失败一次即达阈值。"""
    assert svc.login("ip-mix", "alice", "wrong", now=0.0) is None
    r = svc.refresh("ip-mix", "forged-token", now=0.1)
    assert r.reason == RejectReason.UNKNOWN
    q = svc.logout("ip-mix", "another-forged", now=0.2)
    assert not q.ok and q.reason == RejectReason.UNKNOWN
    audit("login+refresh+logout", "1 failure each, same source",
          "shared counter=3 >= threshold", "source locked")
    assert svc.limiter.is_locked("ip-mix", now=0.3)
    # 锁定后正确口令登录也被拒
    assert svc.login("ip-mix", "alice", "alice-secret", now=0.4) is None


def test_rate_limited_reason_distinct_from_credential_reasons(svc):
    _lock_source(svc, "ip-dist", now=0.0)
    locked_refresh = svc.refresh("ip-dist", "anything", now=1.0)
    locked_logout = svc.logout("ip-dist", "anything", now=1.0)
    assert locked_refresh.reason == RejectReason.RATE_LIMITED
    assert locked_logout.reason == RejectReason.RATE_LIMITED
    credential_reasons = {
        svc.refresh("ip-free", "anything", now=1.0).reason,
    }
    assert RejectReason.RATE_LIMITED not in credential_reasons
    assert locked_refresh.reason not in credential_reasons
    audit("refresh/logout while locked", "locked source vs free source",
          "rate_limited != expired/revoked/replayed/unknown",
          "reasons distinguishable")


# ---- 渐进锁定与平稳恢复 ----


def test_lockout_duration_escalates_and_caps(settings):
    capped = Settings(
        session_ttl_seconds=100.0, max_failed_attempts=3,
        lockout_seconds=30.0, lockout_multiplier=2.0,
        lockout_max_seconds=100.0, calm_seconds=900.0,
    )
    svc2 = AuthService(capped)
    svc2.register_user("alice", "alice-secret", [])
    t = 0.0
    durations = []
    for round_no in range(4):
        for i in range(3):
            svc2.login("ip-esc", "alice", "wrong", now=t + i * 0.1)
        assert svc2.limiter.is_locked("ip-esc", now=t + 1.0)
        until = svc2.limiter.locked_until("ip-esc")
        durations.append(until - (t + 0.2))
        # 跳到锁定期满
        t = until + 0.1
        assert not svc2.limiter.is_locked("ip-esc", now=t)
        t += 0.1
    assert durations == pytest.approx([30.0, 60.0, 100.0, 100.0])
    audit("login x3 per round", "same source, 4 lockouts",
          "duration=base*2^level capped at 100",
          f"durations={durations}")


def test_calm_period_resets_escalation(svc, settings):
    # 第一次锁定：30s（level 1）
    _lock_source(svc, "ip-calm", now=0.0)
    until1 = svc.limiter.locked_until("ip-calm")
    assert until1 == pytest.approx(0.2 + 30.0)
    # 期满后再失败 3 次：升级为 60s（level 2）
    t = until1 + 1.0
    for i in range(3):
        svc.login("ip-calm", "alice", "wrong", now=t + i * 0.1)
    until2 = svc.limiter.locked_until("ip-calm")
    assert until2 == pytest.approx(t + 0.2 + 60.0)
    audit("login x3 after first lock", "no calm period",
          "level=2 -> 60s", f"locked_until={until2}")
    # 平静期（900s）内无新失败：再次触发时回落到基础时长
    t2 = until2 + 1.0 + settings.calm_seconds
    for i in range(3):
        svc.login("ip-calm", "alice", "wrong", now=t2 + i * 0.1)
    until3 = svc.limiter.locked_until("ip-calm")
    assert until3 == pytest.approx(t2 + 0.2 + 30.0)
    audit("login x3 after calm", f"no failures for {settings.calm_seconds}s",
          "level reset -> base 30s", f"locked_until={until3}")


def test_lockout_never_extended_by_failures_during_lock(svc):
    _lock_source(svc, "ip-noext", now=0.0)
    until = svc.limiter.locked_until("ip-noext")
    # 锁定期内持续失败：locked_until 绝不滑动
    for i in range(10):
        svc.limiter.record_failure("ip-noext", now=1.0 + i)
    assert svc.limiter.locked_until("ip-noext") == until
    audit("record_failure x10 during lock", "source locked",
          "locked_until immutable while locked", "no extension")


# ---- 并发一致性 ----


def test_concurrent_refresh_during_lock_all_rejected_token_untouched(svc):
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    _lock_source(svc, "ip-conc", now=1.0)
    n = 8
    barrier = threading.Barrier(n)
    results: list = [None] * n

    def worker(i: int) -> None:
        barrier.wait()
        results[i] = svc.refresh("ip-conc", token.plaintext, now=2.0)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(not r.ok and r.reason == RejectReason.RATE_LIMITED for r in results)
    # 没有任何新凭证产生，旧凭证状态不变
    assert svc.sessions.validate(token.plaintext, now=2.1) is not None
    audit(f"refresh x{n} concurrent during lock", "barrier sync, locked source",
          "admission check serialized", f"all {n} rate_limited, token active")


def test_concurrent_mixed_failures_lock_exactly_once(svc):
    """并发混合失败（登录+换发+注销）：计数精确，拒绝结论一致。"""
    n = 12
    barrier = threading.Barrier(n)
    outcomes: list = [None] * n

    def worker(i: int) -> None:
        barrier.wait()
        kind = i % 3
        if kind == 0:
            outcomes[i] = ("login", svc.login("ip-mixc", "alice", "wrong", now=1.0))
        elif kind == 1:
            outcomes[i] = ("refresh", svc.refresh("ip-mixc", f"forged-{i}", now=1.0))
        else:
            outcomes[i] = ("logout", svc.logout("ip-mixc", f"forged-{i}", now=1.0))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 全部失败（无一成功），且 12 次失败必然越过阈值 3：来源已锁定
    assert all(
        (o[1] is None) if o[0] == "login" else (not o[1].ok) for o in outcomes
    )
    assert svc.limiter.is_locked("ip-mixc", now=1.5)
    # 锁定后到达的同类请求一律 rate_limited，结论一致
    r = svc.refresh("ip-mixc", "forged-x", now=2.0)
    assert r.reason == RejectReason.RATE_LIMITED
    audit("mixed failures x12 concurrent", "login/refresh/logout same source",
          "shared lock-serialized counter", "locked; later ops rate_limited")


# ---- 有界状态管理 ----


def _bounded_svc(max_sources: int, idle: float = 3600.0) -> AuthService:
    s = Settings(
        session_ttl_seconds=100.0, max_failed_attempts=3,
        lockout_seconds=30.0, max_sources=max_sources,
        source_idle_seconds=idle,
    )
    svc = AuthService(s)
    svc.register_user("alice", "alice-secret", [])
    return svc


def test_source_capacity_bounded_and_deterministic_eviction():
    svc = _bounded_svc(max_sources=3)
    for i, name in enumerate(["s1", "s2", "s3"]):
        svc.limiter.record_failure(name, now=float(i))
    assert svc.limiter.tracked_sources() == 3
    # 第 4 个来源：容量满 -> 确定性淘汰（无未决失败优先，再按最旧+字典序）
    svc.limiter.record_failure("s4", now=3.0)
    assert svc.limiter.tracked_sources() == 3
    # s1..s3 都有 1 次未决失败，s4 入场后也有；最早活动的 s1 应已被淘汰：
    # s1 的失败序列被容量规则回收，重新计入从 0 开始
    svc.limiter.record_failure("s1", now=4.0)  # s1 重新入场，淘汰下一个最旧的
    assert svc.limiter.tracked_sources() == 3
    audit("record_failure 5 sources, cap=3", "s1..s4 sequential",
          "evict (no-failures first, then oldest, then name)",
          "tracked=3, deterministic")


def test_locked_source_never_evicted():
    svc = _bounded_svc(max_sources=2)
    # s1 进入锁定
    for i in range(3):
        svc.limiter.record_failure("s1", now=float(i) * 0.1)
    assert svc.limiter.is_locked("s1", now=1.0)
    svc.limiter.record_failure("s2", now=1.0)
    # 容量满（s1 锁定 + s2），s3 入场只能淘汰 s2，绝不能提前放行 s1
    svc.limiter.record_failure("s3", now=2.0)
    assert svc.limiter.tracked_sources() == 2
    assert svc.limiter.is_locked("s1", now=2.0)
    audit("insert s3 with cap=2", "s1 locked, s2 idle-ish",
          "locked sources are not eviction candidates",
          "s2 evicted, s1 still locked")


def test_idle_sources_reclaimed_before_eviction():
    svc = _bounded_svc(max_sources=2, idle=10.0)
    svc.limiter.record_failure("old-1", now=0.0)
    svc.limiter.record_failure("old-2", now=1.0)
    # 两个来源都已闲置超期：新来源入场时先回收闲置，而非淘汰活跃序列
    svc.limiter.record_failure("new-1", now=100.0)
    assert svc.limiter.tracked_sources() == 1
    svc.limiter.record_failure("new-2", now=100.1)
    assert svc.limiter.tracked_sources() == 2
    audit("insert after idle timeout", "old-1/old-2 idle>10s",
          "idle reclaimed on insert", "tracked<=2, memory bounded")


def test_active_failure_sequence_not_cleared_by_reclaim():
    """正在累计的失败序列（未闲置）不能被回收/淘汰错误清零。"""
    svc = _bounded_svc(max_sources=2, idle=100.0)
    svc.limiter.record_failure("hot", now=50.0)
    svc.limiter.record_failure("hot", now=51.0)
    svc.limiter.record_failure("other", now=52.0)
    # 容量满时插入第三方：other（仅 1 次失败且更旧的活动）被淘汰，
    # hot 的连续失败序列保留——再失败 1 次即触发锁定
    svc.limiter.record_failure("third", now=53.0)
    triggered = svc.limiter.record_failure("hot", now=54.0)
    assert triggered is True
    assert svc.limiter.is_locked("hot", now=54.1)
    audit("insert third with cap=2", "hot has 2 pending failures",
          "eviction prefers fewer/older sequences",
          "hot sequence preserved, 3rd failure locks")
