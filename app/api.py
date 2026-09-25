"""FastAPI 路由层：登录、刷新、登出、受保护资源。

错误码映射：rate_limited -> 429，forbidden -> 403，其余认证失败 -> 401。
响应体只携带可区分的 code，不回显任何凭证内容。
"""
from __future__ import annotations

import time
from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.models import Permission
from app.service import AuthError, AuthService

_STATUS_BY_CODE = {
    "rate_limited": 429,
    "forbidden": 403,
}


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenRequest(BaseModel):
    token: str


class AccessRequest(BaseModel):
    token: str
    action: str
    resource: str


def _source_of(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def create_app(service: AuthService,
               clock: Callable[[], float] = time.time) -> FastAPI:
    app = FastAPI(title="session-authz")

    @app.exception_handler(AuthError)
    def _auth_error(_: Request, exc: AuthError) -> JSONResponse:
        status = _STATUS_BY_CODE.get(exc.code, 401)
        return JSONResponse(status_code=status,
                            content={"error": exc.code, "message": str(exc)})

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/login")
    def login(body: LoginRequest, request: Request) -> dict[str, str]:
        token = service.login(body.username, body.password,
                              _source_of(request), clock())
        return {"token": token}

    @app.post("/refresh")
    def refresh(body: TokenRequest, request: Request) -> dict[str, str]:
        token = service.refresh(body.token, _source_of(request), clock())
        return {"token": token}

    @app.post("/logout")
    def logout(body: TokenRequest) -> dict[str, str]:
        service.logout(body.token)
        return {"status": "revoked"}

    @app.post("/authorize")
    def authorize(body: AccessRequest) -> dict[str, str]:
        subject = service.authorize(
            body.token, Permission(body.action, body.resource), clock())
        return {"subject": subject, "verdict": "allow"}

    return app
