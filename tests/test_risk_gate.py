"""统一来源风险准入、渐进式锁定/平稳恢复、有界状态回收与并发一致性。

每个用例通过 audit(...) 打印请求输入 / 判定依据 / 最终结论；
敏感值只用指纹，日志中绝不出现明文凭证或口令。
"""
from __future__ import annotations

import threading

from app.models import RejectReason

from .conftest import audit


def _lock_source(svc, source: str, now: float, times: int = 3):
    """连续失败 times 次触发该来源锁定。"""
    for _ in range(times):
        svc.limiter.record_failure(source, now=now)


# ---- 锁定期内敏感操作被拒且凭证状态不变 ----

def test_refresh_blocked_while_locked_leaves_credentials_untouched(svc):
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    _lock_source(svc, "ip-lock", now=1.0)
    assert svc.limiter.is_locked("ip-lock", now=2.0)

    # 锁定期内换发：直接拒绝，不产生新凭证，旧凭证仍 ACTIVE
    result = svc.refresh(token.plaintext, now=2.0, source="ip-lock")
    assert result.ok is False
    assert result.reason == RejectReason.RATE_LIMITED
    assert result.token is None
    assert svc.sessions.validate(token.plaintext, now=2.0) is not None
    audit("refresh", "source=ip-lock valid token while locked",
          "gate rejected before touching credential",
          "rate_limited; old token still active")

    # 期满恢复后第一次换发照常成功
    recovered = svc.refresh(token.plaintext, now=35.0, source="ip-lock")
    assert recovered.ok and recovered.token is not None
    assert svc.sessions.validate(recovered.token.plaintext, now=35.1) is not None
    audit("refresh", "source=ip-lock after lockout expired",
          "gate admitted, counter reset", "rotated ok")


def test_logout_blocked_while_locked_leaves_credentials_untouched(svc):
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    _lock_source(svc, "ip-lo", now=1.0)

    # 锁定期内注销：拒绝且凭证状态不变
    result = svc.logout(token.plaintext, source="ip-lo", now=2.0)
    assert result.ok is False
    assert result.reason == RejectReason.RATE_LIMITED
    assert result.changed is False
    assert svc.sessions.validate(token.plaintext, now=2.0) is not None
    audit("logout", "source=ip-lo valid token while locked",
          "gate rejected before revoke", "rate_limited; token still active")

    after = svc.logout(token.plaintext, source="ip-lo", now=35.0)
    assert after.ok and after.changed is True
    assert svc.sessions.classify(token.plaintext, now=35.1) == RejectReason.REVOKED
    audit("logout", "source=ip-lo after lockout expired", "gate admitted", "revoked ok")


def test_first_normal_op_after_expiry_succeeds(svc):
    _lock_source(svc, "ip-rec", now=0.0)
    assert svc.limiter.is_locked("ip-rec", now=10.0)
    # 恢复后第一次正常登录立即成功
    token = svc.login("ip-rec", "alice", "alice-secret", now=30.1)
    assert token is not None
    snap = svc.limiter.snapshot("ip-rec")
    assert snap is not None and snap.failures == 0 and snap.locked_until is None
    audit("login", "source=ip-rec first op after expiry",
          "lock expired + success clears counter", "ok")


# ---- 限流原因与凭证原因可区分 ----

def test_ratelimited_distinct_from_credential_reasons(svc):
    # 来源 A：锁定 -> 对一张有效凭证换发，结论是 rate_limited 而非凭证问题
    good = svc.sessions.issue("alice", frozenset(), now=0.0)
    _lock_source(svc, "ip-a", now=1.0)
    ra = svc.refresh(good.plaintext, now=2.0, source="ip-a")
    assert ra.reason == RejectReason.RATE_LIMITED
    audit("refresh", "source=ip-a locked + valid token", "gate", "rate_limited")

    # 来源 B：未锁定 -> 未知凭证，结论是 unknown（凭证原因）
    rb = svc.refresh("made-up-token", now=2.0, source="ip-b")
    assert rb.reason == RejectReason.UNKNOWN
    audit("refresh", "source=ip-b unknown token", "credential lookup", "unknown")

    # 过期 / 已撤销 / 被重放依旧是凭证原因
    t_exp = svc.sessions.issue("alice", frozenset(), now=0.0)
    assert svc.refresh(t_exp.plaintext, now=200.0, source="ip-b").reason \
        == RejectReason.EXPIRED
    t_rev = svc.sessions.issue("alice", frozenset(), now=0.0)
    svc.logout(t_rev.plaintext, source="ip-b", now=1.0)
    assert svc.refresh(t_rev.plaintext, now=2.0, source="ip-b").reason \
        == RejectReason.REVOKED
    t_rp = svc.sessions.issue("alice", frozenset(), now=0.0)
    svc.refresh(t_rp.plaintext, now=1.0, source="ip-b")
    assert svc.refresh(t_rp.plaintext, now=1.5, source="ip-b").reason \
        == RejectReason.REPLAYED
    audit("refresh", "expired/revoked/replayed from unlocked source",
          "credential reasons", "distinct from rate_limited")


def test_logout_unknown_token_counts_as_failure(svc):
    # 未知凭证注销：连续 3 次后来源锁定；幂等重复注销不计风险
    t = svc.sessions.issue("alice", frozenset(), now=0.0)
    svc.logout(t.plaintext, source="ip-u", now=1.0)
    for _ in range(3):
        r = svc.logout(t.plaintext, source="ip-u", now=2.0)
        assert r.reason == RejectReason.REVOKED
    assert not svc.limiter.is_locked("ip-u", now=3.0)
    audit("logout", "repeat revoke of revoked token", "idempotent, not counted",
          "not locked")

    for i in range(3):
        r = svc.logout("nonexistent", source="ip-u2", now=float(i))
        assert r.reason == RejectReason.UNKNOWN
    assert svc.limiter.is_locked("ip-u2", now=3.0)
    audit("logout", "unknown token x3", "each counts as failure", "locked")


# ---- 渐进式锁定与平稳恢复 ----

def test_progressive_lockout_durations(settings):
    # 平稳期足够长：连续多档锁定期间等级不回落
    from app.rate_limit import RateLimiter

    rl = RateLimiter(
        type(settings)(
            max_failed_attempts=3,
            lockout_seconds=30.0,
            lockout_multiplier=2.0,
            max_lockout_seconds=120.0,
            calm_seconds=10_000.0,
            max_tracked_sources=100,
        )
    )
    s = "ip-prog"
    # 第 1 档：30s
    for _ in range(3):
        rl.record_failure(s, now=0.0)
    assert abs(rl.locked_until(s) - 30.0) < 1e-9
    assert rl.snapshot(s).level == 1
    audit("lock", "source=ip-prog 1st trigger", "base duration", "30s level=1")
    # 第 2 档：60s（在上一档期满之后、平稳期之内触发）
    for _ in range(3):
        rl.record_failure(s, now=30.1)
    assert rl.snapshot(s).level == 2
    assert abs(rl.locked_until(s) - 90.1) < 1e-9
    audit("lock", "source=ip-prog 2nd trigger", "30*2", "60s level=2")
    # 第 3 档 120s 封顶（max_lockout_seconds=120），之后不再变长
    for _ in range(3):
        rl.record_failure(s, now=90.2)
    snap3 = rl.snapshot(s)
    assert snap3.level == 3
    assert abs(snap3.locked_until - 210.2) < 1e-9
    for _ in range(3):
        rl.record_failure(s, now=210.3)
    snap4 = rl.snapshot(s)
    assert snap4.level == 4
    assert abs(snap4.locked_until - 330.3) < 1e-9  # 仍只加封顶值 120
    audit("lock", "source=ip-prog levels 3-4", "2x until cap=120",
          "duration capped at 120s")


def test_calm_period_resets_level(settings):
    from app.rate_limit import RateLimiter

    rl = RateLimiter(
        type(settings)(
            max_failed_attempts=3,
            lockout_seconds=30.0,
            lockout_multiplier=2.0,
            max_lockout_seconds=120.0,
            calm_seconds=20.0,
            max_tracked_sources=100,
        )
    )
    s = "ip-calm"
    for _ in range(3):
        rl.record_failure(s, now=0.0)   # level 1, until=30, 期满=30
    for _ in range(3):
        rl.record_failure(s, now=30.1)  # level 2, until=90.1, 期满=90.1
    assert rl.snapshot(s).level == 2
    # 距锁定期满超过平稳期（20s）后再触发：等级回到基础档
    for _ in range(3):
        rl.record_failure(s, now=110.2)  # 110.2-90.1=20.1 > calm
    snap = rl.snapshot(s)
    assert snap.level == 1
    assert abs(snap.locked_until - 140.2) < 1e-9  # 110.2 + 30
    audit("lock", "source=ip-calm after calm window",
          "calm measured from lock expiry", "level reset, 30s again")


def test_lock_does_not_extend_on_blocked_attempts(svc):
    s = "ip-ext"
    _lock_source(svc, s, now=0.0)
    until_first = svc.limiter.locked_until(s)
    # 锁定期内的失败尝试经 gate 被拒，不应续期
    for i in range(5):
        svc.refresh("whatever", now=10.0 + i, source=s)
        assert svc.limiter.locked_until(s) == until_first
    audit("refresh x5", "source=ip-ext attempts during lock",
          "gate rejects, no recount", "locked_until unchanged")


# ---- 并发下计数与拒绝结论一致 ----

def test_concurrent_failures_counted_exactly_across_gate(svc):
    n = 20
    barrier = threading.Barrier(n)
    triggered: list[bool] = [False] * n

    def worker(i: int) -> None:
        barrier.wait()
        # 经由 gate 计一次失败：达阈值后进入同一串行区间的请求会被拒
        with svc.limiter.gate("ip-c1", now=1.0) as held:
            if held.admitted:
                triggered[i] = held.report_failure(now=1.0)
            else:
                triggered[i] = False

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 阈值 3：恰好前 3 个串行请求触发 1 次锁定，其余在锁定期被拒
    assert sum(triggered) == 1
    assert svc.limiter.is_locked("ip-c1", now=1.5)
    audit("gate failure x20 concurrent", "barrier sync, same source",
          "stripe-serialized", "exact count=3, 1 lockout, 17 rejected")


def test_concurrent_refresh_all_rejected_during_lock(svc):
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    _lock_source(svc, "ip-c2", now=1.0)
    n = 12
    barrier = threading.Barrier(n)
    results: list = [None] * n

    def worker(i: int) -> None:
        barrier.wait()
        results[i] = svc.refresh(token.plaintext, now=2.0, source="ip-c2")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(r.reason == RejectReason.RATE_LIMITED for r in results)
    assert all(not r.ok for r in results)
    # 凭证没有被任何一个并发请求改动
    assert svc.sessions.validate(token.plaintext, now=2.1) is not None
    audit("refresh x12 concurrent", "locked source, valid token",
          "every request hits gate first", "12x rate_limited, token intact")


def test_concurrent_sensitive_failures_lead_to_one_consistent_lock(svc):
    n = 12
    barrier = threading.Barrier(n)
    outcomes: list = [None] * n

    def worker(i: int) -> None:
        barrier.wait()
        outcomes[i] = svc.refresh("forged-credential", now=1.0, source="ip-c3")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 前 3 个（串行顺序下）拿到凭证原因并计数，第 4 个起来源已锁定
    credential_failures = [
        o for o in outcomes if o.reason == RejectReason.UNKNOWN
    ]
    rate_limited = [
        o for o in outcomes if o.reason == RejectReason.RATE_LIMITED
    ]
    assert len(credential_failures) == 3
    assert len(rate_limited) == n - 3
    assert svc.limiter.is_locked("ip-c3", now=1.1)
    audit("refresh forged x12 concurrent", "same source, barrier sync",
          "3 counted then locked, rest rejected",
          f"unknown=3, rate_limited={n - 3}")


def test_concurrent_refresh_rotation_is_atomic_under_gate(svc):
    """准入与轮换串行化叠加：并发换发恰好一个成功，锁定来源全部被拒。"""
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    n = 16
    barrier = threading.Barrier(n)
    outcomes: list = [None] * n

    def worker(i: int) -> None:
        barrier.wait()
        outcomes[i] = svc.refresh(token.plaintext, now=1.0, source="ip-rot")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [o for o in outcomes if o.ok]
    assert len(winners) == 1
    # 其余：恰好一个重放（racing，良性不计风险），且该来源从未被锁定
    rejected = [o for o in outcomes if not o.ok]
    assert len(rejected) == n - 1
    assert svc.limiter.snapshot("ip-rot") is None  # racing 不计数，无状态残留
    audit("refresh x16 concurrent", "valid token, unlocked source",
          "gate+rotation both serialized",
          "1 rotated, rest racing(replayed), no lockout")


# ---- 来源状态回收与容量边界 ----

def test_idle_sources_reclaimed_after_success(svc):
    # 一次失败后成功：计数归零；升级等级仍在平稳窗口内时保留，
    # 超过平稳窗口的归零来源成为闲置项并被立即回收
    svc.limiter.record_failure("ip-idle", now=0.0)
    assert svc.limiter.tracked_count() == 1
    svc.limiter.record_success("ip-idle", now=25.0)  # > calm_seconds(20)
    assert svc.limiter.tracked_count() == 0
    audit("record_success", "source=ip-idle failed then succeeded past calm",
          "zeroed idle entry removed", "tracked=0")

    # 仍在升级平稳窗口内的归零来源保留，超过平稳窗口后确定性回收
    svc.limiter.record_failure("ip-keep2", now=0.0)
    svc.limiter.record_failure("ip-keep2", now=1.0)
    svc.limiter.record_failure("ip-keep2", now=2.0)  # 锁定 level=1，期满=32
    assert svc.limiter.is_locked("ip-keep2", now=31.0)
    assert not svc.limiter.is_locked("ip-keep2", now=33.0)  # 期满解除
    with svc.limiter.gate("ip-other", now=40.0):
        pass  # 40-32=8 < calm(20)，等级保留
    assert svc.limiter.snapshot("ip-keep2") is not None
    with svc.limiter.gate("ip-other", now=53.0):
        pass  # 53-32=21 > calm，确定性回收
    assert svc.limiter.snapshot("ip-keep2") is None
    audit("gate", "expired source kept through calm, reaped after",
          "deterministic idle reaping", "retained then reclaimed")

    # 从未失败的正常敏感操作根本不占用风险表
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    assert svc.refresh(token.plaintext, now=1.0, source="ip-clean").ok
    assert svc.limiter.tracked_count() == 0
    audit("refresh", "clean source, no failure", "no state allocated", "tracked=0")
    # 纯准入（未回报任何失败/成功）也不留空占位
    with svc.limiter.gate("ip-clean2", now=2.0):
        assert svc.limiter.tracked_count() == 1  # 区间内有 in_gate 占位
    assert svc.limiter.tracked_count() == 0
    audit("gate", "source=ip-clean2 admitted, no outcome",
          "placeholder removed on exit", "tracked=0")


def test_locked_and_accumulating_sources_never_evicted_early(svc):
    # 仍在锁定期的来源不会被回收
    _lock_source(svc, "ip-keep", now=0.0)
    with svc.limiter.gate("other", now=10.0):
        pass
    assert svc.limiter.snapshot("ip-keep") is not None
    assert svc.limiter.is_locked("ip-keep", now=10.0)
    audit("gate", "locked source while sweeping others",
          "locked state protected", "still locked, retained")

    # 正在累计失败的来源不会被回收
    svc.limiter.record_failure("ip-half", now=0.0)
    svc.limiter.record_failure("ip-half", now=1.0)
    with svc.limiter.gate("other2", now=2.0):
        pass
    assert svc.limiter.snapshot("ip-half") is not None
    assert svc.limiter.snapshot("ip-half").failures == 2
    audit("gate", "source mid failure sequence", "nonzero failures protected",
          "counter kept")


def test_tracking_is_bounded_by_capacity(svc):
    cap = svc.settings.max_tracked_sources  # 100
    # 填满容量：全部为不可回收的锁定来源
    for i in range(cap):
        _lock_source(svc, f"ip-full-{i}", now=0.0)
    assert svc.limiter.tracked_count() == cap
    # 容量已满且无闲置可回收：新失败被保安全丢弃，表不增长
    assert svc.limiter.record_failure("ip-overflow", now=1.0) is False
    assert svc.limiter.tracked_count() == cap
    audit("record_failure", "table full of locked sources",
          "no reclaimable entry, fail closed", "not counted, bounded at cap")


def test_eviction_is_deterministic():
    """同一操作序列下，回收结果必须逐次一致（排序删除，可复现）。"""
    from app.config import Settings
    from app.rate_limit import RateLimiter

    def run():
        rl = RateLimiter(Settings(max_failed_attempts=3, max_tracked_sources=50))
        for i in range(10):
            src = f"s{i}"
            rl.record_failure(src, now=0.0)
            rl.record_success(src, now=0.0)  # 归零且无升级，立即回收
        assert rl.tracked_count() == 0
        # 再造一批不可回收（锁定）来源到容量上限，之后的新失败保安全丢弃
        for i in range(50):
            for _ in range(3):
                rl.record_failure(f"locked-{i}", now=1.0)
        assert rl.tracked_count() == 50
        rl.record_failure("overflow", now=2.0)
        return rl.tracked_count()

    assert run() == run() == 50
    audit("eviction", "two limiters, identical input sequence",
          "sorted deterministic reclamation + hard cap", "identical size=50")
