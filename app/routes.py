"""HTTP 接口：登录、刷新、登出、受保护资源示例。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.deps import get_service, now, require
from app.service import AuthService

router = APIRouter()


class LoginBody(BaseModel):
    username: str
    password: str


class TokenBody(BaseModel):
    token: str


def _source(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/login")
def login(
    body: LoginBody,
    request: Request,
    svc: AuthService = Depends(get_service),
):
    # 锁定、口令错误、用户不存在对外一律 401，不泄露具体原因
    token = svc.login(_source(request), body.username, body.password, now())
    if token is None:
        raise HTTPException(status_code=401, detail="invalid credentials")
    return {"token": token.plaintext, "expires_at": token.record.expires_at}


@router.post("/refresh")
def refresh(
    body: TokenBody,
    request: Request,
    svc: AuthService = Depends(get_service),
):
    result = svc.refresh(_source(request), body.token, now())
    if not result.ok or result.token is None:
        if result.reason is not None and result.reason.value == "rate_limited":
            # 限流/锁定拒绝：不暴露凭证是否有效
            raise HTTPException(status_code=429, detail="rate_limited")
        # 拒绝原因可区分：expired / revoked / replayed / unknown
        raise HTTPException(status_code=401, detail=result.reason.value)
    return {
        "token": result.token.plaintext,
        "expires_at": result.token.record.expires_at,
    }


@router.post("/logout", status_code=204)
def logout(
    body: TokenBody,
    request: Request,
    svc: AuthService = Depends(get_service),
):
    result = svc.logout(_source(request), body.token, now())
    if not result.ok and result.reason is not None and result.reason.value == "rate_limited":
        raise HTTPException(status_code=429, detail="rate_limited")
    # 其余情况一律 204：不暴露凭证是否存在/有效
    return None


@router.get("/protected/documents")
def read_documents(token: str = Depends(require("documents:read"))):
    return {"documents": ["doc-1", "doc-2"]}


@router.post("/protected/documents")
def write_document(token: str = Depends(require("documents:write"))):
    return {"created": True}
