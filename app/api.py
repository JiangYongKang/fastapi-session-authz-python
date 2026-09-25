"""FastAPI 路由层：登录、刷新、登出、受保护资源。"""
from __future__ import annotations

from fastapi import FastAPI

from app.service import AuthService


def create_app(service: AuthService) -> FastAPI:
    app = FastAPI(title="session-authz")
    app.state.service = service

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
