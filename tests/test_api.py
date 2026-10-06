"""HTTP 层集成：状态码与拒绝原因一致，锁定边界，接口不泄露敏感细节。"""
from __future__ import annotations

import time

from fastapi.testclient import TestClient

import main
from app.deps import get_service

from .conftest import audit


def _client(svc):
    client = TestClient(main.app)
    main.app.dependency_overrides[get_service] = lambda: svc
    return client


def test_login_and_procted_access(svc):
    with _client(svc) as c:
        r = c.post("/login", json={"username": "alice", "password": "alice-secret"})
        assert r.status_code == 200
        token = r.json()["token"]
        audit("POST /login", "alice + password", "pbkdf2 verify ok", "200 token issued")

        r = c.get("/protected/documents",
                  headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        audit("GET /protected/documents", "bearer token", "matched=documents:read",
              "200 allowed")

        r = c.post("/protected/documents",
                   headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403
        audit("POST /protected/documents", "alice requires documents:write",
              "no covering grant", "403 denied")

        r = c.get("/protected/documents")
        assert r.status_code == 401


def test_bad_login_is_generic(svc):
    with _client(svc) as c:
        r1 = c.post("/login", json={"username": "ghost", "password": "x"})
        r2 = c.post("/login", json={"username": "alice", "password": "bad"})
        assert r1.status_code == r2.status_code == 401
        assert r1.json() == r2.json() == {"detail": "invalid credentials"}
        audit("POST /login", "unknown user / wrong password",
              "identical response body", "401 generic")


def test_refresh_status_codes_and_reasons(svc):
    with _client(svc) as c:
        token = c.post(
            "/login", json={"username": "alice", "password": "alice-secret"}
        ).json()["token"]
        r = c.post("/refresh", json={"token": token})
        assert r.status_code == 200
        new_token = r.json()["token"]
        audit("POST /refresh", "valid old token", "rotated atomically",
              "200 new token")
        # 重放：可区分的原因码
        r2 = c.post("/refresh", json={"token": token})
        assert r2.status_code == 401
        assert r2.json()["detail"] == "replayed"
        audit("POST /refresh", "old token reused", "rotated within grace",
              "401 replayed")
        # 撤销
        c.post("/logout", json={"token": new_token})
        r3 = c.post("/refresh", json={"token": new_token})
        assert r3.status_code == 401 and r3.json()["detail"] == "revoked"
        audit("POST /refresh", "token after logout", "status=revoked",
              "401 revoked")
        # 未知凭证
        r4 = c.post("/refresh", json={"token": "made-up"})
        assert r4.status_code == 401 and r4.json()["detail"] == "unknown"


def test_expired_token_rejected_as_expired(settings, svc):
    settings2 = type(settings)(
        session_ttl_seconds=0.2,
        max_failed_attempts=3,
        lockout_seconds=30.0,
        replay_grace_seconds=1.0,
    )
    from app.service import AuthService
    short_svc = AuthService(settings2)
    short_svc.roles.define_role("viewer", ["documents:read"])
    short_svc.register_user("alice", "alice-secret", ["viewer"])
    with _client(short_svc) as c:
        token = c.post(
            "/login", json={"username": "alice", "password": "alice-secret"}
        ).json()["token"]
        time.sleep(0.3)
        r = c.post("/refresh", json={"token": token})
        assert r.status_code == 401 and r.json()["detail"] == "expired"
        audit("POST /refresh", "ttl=0.2s, waited 0.3s", "expires_at passed",
              "401 expired")
        r2 = c.get("/protected/documents",
                   headers={"Authorization": f"Bearer {token}"})
        assert r2.status_code == 403


def test_lockout_boundary_over_http(svc):
    with _client(svc) as c:
        for _ in range(3):
            assert c.post(
                "/login", json={"username": "alice", "password": "bad"}
            ).status_code == 401
        audit("POST /login x3", "same source, bad password",
              "failure threshold reached", "locked")
        # 锁定期内：正确口令也拒绝，且响应体与口令错误时相同
        r = c.post("/login", json={"username": "alice", "password": "alice-secret"})
        assert r.status_code == 401
        assert r.json() == {"detail": "invalid credentials"}
        audit("POST /login", "correct password during lock", "source locked",
              "401 generic")


def test_locked_source_sensitive_ops_return_429(svc):
    """锁定期间：/refresh 与 /logout 返回 429 rate_limited，且凭证状态不变。"""
    with _client(svc) as c:
        token = c.post(
            "/login", json={"username": "alice", "password": "alice-secret"}
        ).json()["token"]
        for _ in range(3):
            assert c.post(
                "/login", json={"username": "alice", "password": "bad"}
            ).status_code == 401
        audit("POST /login x3", "same source, bad password",
              "shared risk counter >= 3", "source locked")

        r = c.post("/refresh", json={"token": token})
        assert r.status_code == 429
        assert r.json() == {"detail": "rate_limited"}
        audit("POST /refresh", "valid token, locked source",
              "admission=locked, credential not inspected", "429 rate_limited")

        r2 = c.post("/logout", json={"token": token})
        assert r2.status_code == 429
        assert r2.json() == {"detail": "rate_limited"}
        audit("POST /logout", "valid token, locked source",
              "admission=locked, credential not inspected", "429 rate_limited")

        # 凭证未被改动：锁定期间它没有被轮换也没有被撤销，
        # 锁定期内受保护端点仍按其自身状态判定（凭证本身仍有效）
        r3 = c.get("/protected/documents",
                   headers={"Authorization": f"Bearer {token}"})
        assert r3.status_code == 200
        audit("GET /protected/documents", "token after rejected refresh/logout",
              "status=active unchanged", "200 allowed")


def test_logout_response_does_not_leak_token_validity(svc):
    """注销接口对未知/有效凭证响应一致（204），不暴露凭证是否存在。"""
    with _client(svc) as c:
        token = c.post(
            "/login", json={"username": "alice", "password": "alice-secret"}
        ).json()["token"]
        r_valid = c.post("/logout", json={"token": token})
        r_unknown = c.post("/logout", json={"token": "made-up"})
        assert r_valid.status_code == r_unknown.status_code == 204
        assert r_valid.content == r_unknown.content
        audit("POST /logout", "valid token vs unknown token",
              "identical 204 empty body", "no validity oracle")
