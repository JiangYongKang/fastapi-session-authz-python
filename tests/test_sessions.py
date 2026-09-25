"""凭证生命周期：重放、并发刷新、过期、撤销，拒绝原因可区分。"""
import threading

import pytest

from app.models import RejectReason
from app.service import AuthError
from app.session_store import RefreshRejected, SessionStore


def test_refresh_rotation_single_use(service, clock):
    token = service.login("alice", "pw-alice", "ip-1", clock())
    new_token = service.refresh(token, "ip-1", clock())
    assert new_token != token
    with pytest.raises(AuthError) as exc:
        service.refresh(token, "ip-1", clock())
    assert exc.value.code == "session_replayed"


def test_concurrent_refresh_only_one_wins(settings):
    store = SessionStore(settings.session_ttl_seconds)
    record = store.issue("alice", ["reader"], now=0.0)
    won, rejected = [], []

    def worker():
        try:
            won.append(store.refresh(record.token_id, now=1.0))
        except RefreshRejected as exc:
            rejected.append(exc.reason)

    threads = [threading.Thread(target=worker) for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(won) == 1, "并发刷新不得产生两个生效的新凭证"
    assert len(rejected) == 31
    assert set(rejected) == {RejectReason.REPLAYED}
    # 唯一胜出的新凭证可用，旧凭证依旧拒绝
    store.validate(won[0].token_id, now=2.0)
    with pytest.raises(RefreshRejected):
        store.validate(record.token_id, now=2.0)


def test_expired_token_rejected_with_distinct_reason(service, clock):
    token = service.login("alice", "pw-alice", "ip-2", clock())
    clock.advance(101.0)  # 超过 ttl=100
    with pytest.raises(AuthError) as exc:
        service.refresh(token, "ip-2", clock())
    assert exc.value.code == "session_expired"
    with pytest.raises(AuthError) as exc:
        service.authorize(token, _read_docs(), clock())
    assert exc.value.code == "session_expired"


def test_revoked_token_rejected_immediately(service, clock):
    token = service.login("alice", "pw-alice", "ip-3", clock())
    service.logout(token)
    with pytest.raises(AuthError) as exc:
        service.authorize(token, _read_docs(), clock())
    assert exc.value.code == "session_revoked"
    with pytest.raises(AuthError) as exc:
        service.refresh(token, "ip-3", clock())
    assert exc.value.code == "session_revoked"


def test_unknown_token_rejected(service, clock):
    with pytest.raises(AuthError) as exc:
        service.authorize("no-such-token", _read_docs(), clock())
    assert exc.value.code == "session_invalid"


def test_rejection_reasons_are_distinct(service, clock):
    """三类原因两两可区分。"""
    expired = service.login("alice", "pw-alice", "ip-4", clock())
    clock.advance(101.0)
    revoked = service.login("alice", "pw-alice", "ip-4", clock())
    service.logout(revoked)
    rotated = service.login("alice", "pw-alice", "ip-4", clock())
    service.refresh(rotated, "ip-4", clock())

    codes = set()
    for tok in (expired, revoked, rotated):
        with pytest.raises(AuthError) as exc:
            service.authorize(tok, _read_docs(), clock())
        codes.add(exc.value.code)
    assert codes == {"session_expired", "session_revoked", "session_replayed"}


def _read_docs():
    from app.models import Permission
    return Permission("read", "docs/notes")
