"""凭证生命周期：签发、过期、撤销、单次使用轮换，以及并发刷新竞态。"""
from __future__ import annotations

import threading

from app.models import RejectReason

from .conftest import audit


def test_issue_and_validate(svc):
    token = svc.sessions.issue("alice", frozenset({"viewer"}), now=0.0)
    audit("issue", "subject=alice", "ttl=100s", "issued")
    assert svc.sessions.validate(token.plaintext, now=50.0) is not None
    audit("validate", "token_fp=" + token.plaintext[:8], "status=active", "accepted")


def test_expired_rejected_as_expired(svc):
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    decision = svc.authorize(token.plaintext, "documents:read", now=100.1)
    audit("authorize", "ttl_expired", "expires_at=100 now=100.1", "denied:expired")
    assert not decision.allowed
    assert svc.sessions.classify(token.plaintext, now=100.1) == RejectReason.EXPIRED
    # 过期凭证刷新同样按过期拒绝
    result = svc.refresh(token.plaintext, now=100.1)
    assert result.reason == RejectReason.EXPIRED


def test_revoked_rejected_as_revoked(svc):
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    assert svc.logout(token.plaintext).changed is True
    audit("logout", "revoke token", "status=revoked", "revoked")
    assert svc.sessions.classify(token.plaintext, now=10.0) == RejectReason.REVOKED
    result = svc.refresh(token.plaintext, now=10.0)
    assert result.reason == RejectReason.REVOKED
    # 重复撤销幂等，原因保持“已撤销”
    assert svc.logout(token.plaintext).changed is False
    assert svc.sessions.classify(token.plaintext, now=10.0) == RejectReason.REVOKED


def test_reason_priority_expired_vs_revoked(svc):
    """撤销与过期同时成立时，结论稳定且一致地归为“已撤销”。"""
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    svc.logout(token.plaintext)
    assert svc.sessions.classify(token.plaintext, now=999.0) == RejectReason.REVOKED


def test_refresh_single_use_and_replay(svc):
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    r1 = svc.refresh(token.plaintext, now=10.0)
    assert r1.ok and r1.token is not None
    audit("refresh", "old token", "status=active", "rotated,new issued")
    # 旧凭证在宽限窗口内再次使用：判为重放（并发竞争），新链存活
    r2 = svc.refresh(token.plaintext, now=10.5)
    assert r2.reason == RejectReason.REPLAYED
    assert svc.sessions.validate(r1.token.plaintext, now=10.6) is not None
    audit("refresh", "old token reused@10.5", "rotated within grace",
          "denied:replayed(racing),new chain kept")
    # 宽限窗口之外再次重放：判为重放（疑似被盗），整条链吊销
    r3 = svc.refresh(token.plaintext, now=20.0)
    assert r3.reason == RejectReason.REPLAYED
    assert svc.sessions.validate(r1.token.plaintext, now=20.1) is None
    audit("refresh", "old token reused@20", "rotated beyond grace",
          "denied:replayed(stolen),family revoked")


def test_concurrent_refresh_only_one_wins(svc, caplog):
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    barrier = threading.Barrier(8)
    results: list = [None] * 8

    def worker(i: int) -> None:
        barrier.wait()  # 让 8 个请求同时进入 refresh
        results[i] = svc.refresh(token.plaintext, now=1.0)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [r for r in results if r.ok]
    losers = [r for r in results if not r.ok]
    assert len(winners) == 1, f"期望恰好一个胜出，实际 {len(winners)}"
    assert all(r.reason == RejectReason.REPLAYED for r in losers)
    winner_token = winners[0].token.plaintext
    # 竞争结束后胜出凭证可正常使用
    assert svc.sessions.validate(winner_token, now=1.5) is not None
    audit("refresh x8 concurrent", "same old token, barrier sync",
          "lock-serialized check+rotate",
          "1 rotated + 7 replayed; winner_valid=True")
    # 日志不得包含明文凭证
    for record in caplog.records:
        assert token.plaintext not in record.getMessage()
        assert winner_token not in record.getMessage()


def test_rotated_token_expiry_does_not_mask_replay(svc):
    """轮换后的旧凭证即使早已过期，再次使用仍判为 replayed 而非 expired。"""
    token = svc.sessions.issue("alice", frozenset(), now=0.0)
    svc.refresh(token.plaintext, now=10.0)
    assert svc.refresh(token.plaintext, now=999.0).reason == RejectReason.REPLAYED


def test_revoke_subject_kills_all_sessions(svc):
    t1 = svc.sessions.issue("alice", frozenset(), now=0.0)
    t2 = svc.sessions.issue("alice", frozenset(), now=1.0)
    count = svc.sessions.revoke_subject("alice")
    assert count == 2
    assert svc.sessions.validate(t1.plaintext, now=2.0) is None
    assert svc.sessions.validate(t2.plaintext, now=2.0) is None
