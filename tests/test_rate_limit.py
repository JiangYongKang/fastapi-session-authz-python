"""限流与锁定：阈值边界、锁定期、期满恢复、并发计数、敏感信息保护。"""
import logging
import threading

import pytest

from app.rate_limit import RateLimiter
from app.service import AuthError


def test_lockout_threshold_boundary(service, clock):
    """max-1 次失败仍可尝试，第 max 次失败触发锁定。"""
    for i in range(2):  # max=3，前两次仅计数
        with pytest.raises(AuthError) as exc:
            service.login("alice", "wrong", "ip-lock", clock())
        assert exc.value.code == "invalid_credentials"
    with pytest.raises(AuthError):  # 第 3 次失败 -> 锁定
        service.login("alice", "wrong", "ip-lock", clock())
    # 锁定期内即使口令正确也拒绝
    with pytest.raises(AuthError) as exc:
        service.login("alice", "pw-alice", "ip-lock", clock())
    assert exc.value.code == "rate_limited"


def test_lockout_expiry_recovers(service, clock):
    for _ in range(3):
        with pytest.raises(AuthError):
            service.login("alice", "wrong", "ip-exp", clock())
    clock.advance(59.9)
    with pytest.raises(AuthError) as exc:
        service.login("alice", "pw-alice", "ip-exp", clock())
    assert exc.value.code == "rate_limited"
    clock.advance(0.2)  # 锁定期满
    assert service.login("alice", "pw-alice", "ip-exp", clock())


def test_success_resets_failure_count(service, clock):
    for _ in range(2):
        with pytest.raises(AuthError):
            service.login("alice", "wrong", "ip-reset", clock())
    service.login("alice", "pw-alice", "ip-reset", clock())  # 成功清零
    for _ in range(2):  # 重新计数，不应立即锁定
        with pytest.raises(AuthError) as exc:
            service.login("alice", "wrong", "ip-reset", clock())
        assert exc.value.code == "invalid_credentials"


def test_concurrent_failures_counted_exactly_once(settings):
    limiter = RateLimiter(max_failed_attempts=10, lockout_seconds=60,
                          failure_window_seconds=600)

    def worker():
        limiter.record_failure("ip-hot", now=1.0)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    verdict = limiter.check("ip-hot", now=2.0)
    assert verdict.failure_count == 10, "并发失败不得漏计或重复计数"
    assert not verdict.allowed


def test_lockout_not_double_counted_during_lock(service, clock):
    for _ in range(3):
        with pytest.raises(AuthError):
            service.login("alice", "wrong", "ip-dbl", clock())
    for _ in range(5):  # 锁定期内的失败不延长锁定、不重复计数
        with pytest.raises(AuthError):
            service.login("alice", "wrong", "ip-dbl", clock())
    clock.advance(60.0)
    assert service.login("alice", "pw-alice", "ip-dbl", clock())


def test_error_message_does_not_leak_user_existence(service, clock):
    """用户不存在与口令错误的对外表现完全一致。"""
    with pytest.raises(AuthError) as unknown:
        service.login("ghost", "whatever", "ip-leak", clock())
    with pytest.raises(AuthError) as bad_pw:
        service.login("alice", "wrong", "ip-leak", clock())
    assert unknown.value.code == bad_pw.value.code == "invalid_credentials"
    assert str(unknown.value) == str(bad_pw.value)


def test_logs_contain_no_plaintext_credentials(service, clock, caplog):
    from app.models import Permission

    token = service.login("alice", "pw-alice", "ip-log", clock())
    new_token = service.refresh(token, "ip-log", clock())
    with pytest.raises(AuthError):
        service.login("alice", "wrong", "ip-log", clock())
    with caplog.at_level(logging.INFO, logger="app.service"):
        service.authorize(new_token, Permission("read", "docs/x"), clock())
    for record in caplog.records:
        text = record.getMessage()
        assert "pw-alice" not in text and "wrong" not in text
        assert token not in text and new_token not in text, "日志不得出现明文凭证"
