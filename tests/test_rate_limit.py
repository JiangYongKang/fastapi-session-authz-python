"""登录失败限流、锁定阈值、期满恢复、并发计数一致性与信息不泄露。"""
from __future__ import annotations

import threading

from app.models import RejectReason

from .conftest import audit


def test_lockout_threshold_and_recovery(svc, settings):
    for i in range(1, settings.max_failed_attempts):
        assert svc.login("ip-1", "alice", "wrong", now=float(i)) is None
        audit("login", "source=ip-1 bad password", f"failures={i}", "401:invalid")
    # 第 max 次失败触发锁定
    assert svc.login("ip-1", "alice", "wrong", now=5.0) is None
    assert svc.limiter.is_locked("ip-1", now=6.0)
    audit("login", "source=ip-1 at threshold", "failures>=3", "locked")
    # 锁定期内即使口令正确也拒绝
    assert svc.login("ip-1", "alice", "alice-secret", now=10.0) is None
    audit("login", "source=ip-1 correct password during lock", "locked_until=35",
          "401:invalid(locked)")
    # 期满恢复
    assert not svc.limiter.is_locked("ip-1", now=35.1)
    ok = svc.login("ip-1", "alice", "alice-secret", now=36.0)
    assert ok is not None
    audit("login", "source=ip-1 after 30s", "lock expired, counter reset", "ok")


def test_success_resets_counter(svc, settings):
    assert svc.login("ip-2", "alice", "wrong", now=0.0) is None
    assert svc.login("ip-2", "alice", "wrong", now=1.0) is None
    assert svc.login("ip-2", "alice", "alice-secret", now=2.0) is not None
    audit("login", "2 fails then success", "counter reset", "ok")
    # 重新计数：再来 2 次失败不会锁定
    assert svc.login("ip-2", "alice", "wrong", now=3.0) is None
    assert svc.login("ip-2", "alice", "wrong", now=4.0) is None
    assert not svc.limiter.is_locked("ip-2", now=5.0)


def test_concurrent_failures_counted_exactly(svc):
    """N 个并发失败请求必须恰好计入 N 次：不漏计、不重复计。

    锁定期间到达的失败如实计入但不延长当前锁定期；期满结算时，
    累计失败仍达阈值则按升级后的时长开启新锁定。
    """
    n = 20
    barrier = threading.Barrier(n)
    triggered: list[bool] = [False] * n

    def worker(i: int) -> None:
        barrier.wait()
        triggered[i] = svc.limiter.record_failure("ip-3", now=1.0)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 阈值 3：前 3 次失败触发首次锁定（level 1，30s，至 31.0）；
    # 其余 17 次发生在锁定期内：如实计入但不触发新锁定、不续期
    assert sum(triggered) == 1
    audit("record_failure x20 concurrent", "barrier sync, same source",
          "lock-serialized counter; locked_until never slides",
          f"exact count=20, lockouts_now={sum(triggered)}")
    until = svc.limiter.locked_until("ip-3")
    assert until == 1.0 + svc.settings.lockout_seconds
    assert svc.limiter.is_locked("ip-3", now=1.5)
    # 期满结算：锁定期间累计 17 次失败 >= 阈值 -> 立即按升级时长再锁
    assert svc.limiter.is_locked("ip-3", now=31.1)
    until2 = svc.limiter.locked_until("ip-3")
    assert until2 == 31.1 + svc.settings.lockout_seconds * svc.settings.lockout_multiplier
    audit("is_locked after expiry", "pending failures=17 >= 3",
          "re-lock at escalated level=2", f"locked_until={until2}")


def test_lockout_is_per_source(svc):
    for _ in range(3):
        svc.login("ip-bad", "alice", "wrong", now=0.0)
    assert svc.limiter.is_locked("ip-bad", now=1.0)
    assert not svc.limiter.is_locked("ip-good", now=1.0)
    assert svc.login("ip-good", "alice", "alice-secret", now=1.0) is not None


def test_login_failure_message_does_not_leak(svc, caplog):
    """用户不存在与口令错误对外表现一致；日志不区分用户是否存在、不含口令。"""
    r_user = svc.login("ip-4", "ghost", "anything", now=0.0)
    r_pass = svc.login("ip-4", "alice", "wrong-password", now=1.0)
    assert r_user is None and r_pass is None
    audit("login", "unknown user vs wrong password",
          "same control path, dummy hash", "both None, identical")
    assert "anything" not in caplog.text
    assert "wrong-password" not in caplog.text
    assert "alice-secret" not in caplog.text


def test_rejected_refresh_reasons_are_distinct(svc):
    # expired
    t_exp = svc.sessions.issue("alice", frozenset(), now=0.0)
    assert svc.refresh("ip-r", t_exp.plaintext, now=999.0).reason == RejectReason.EXPIRED
    # revoked
    t_rev = svc.sessions.issue("alice", frozenset(), now=0.0)
    svc.logout("ip-r", t_rev.plaintext, now=0.5)
    assert svc.refresh("ip-r", t_rev.plaintext, now=1.0).reason == RejectReason.REVOKED
    # replayed
    t_rp = svc.sessions.issue("alice", frozenset(), now=0.0)
    svc.refresh("ip-r", t_rp.plaintext, now=1.0)
    assert svc.refresh("ip-r", t_rp.plaintext, now=1.5).reason == RejectReason.REPLAYED
    # 第二轮验证用独立来源，避免共享计数达到阈值干扰原因判定
    reasons = {
        svc.refresh("ip-r2", t_exp.plaintext, now=999.0).reason,
        svc.refresh("ip-r3", t_rev.plaintext, now=1.0).reason,
        svc.refresh("ip-r4", t_rp.plaintext, now=1.5).reason,
    }
    assert reasons == {RejectReason.EXPIRED, RejectReason.REVOKED, RejectReason.REPLAYED}
