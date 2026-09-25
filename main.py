"""服务入口：装配默认配置并启动 FastAPI 应用。"""
import uvicorn

from app.api import create_app
from app.authz import Authorizer
from app.config import DEFAULT_SETTINGS
from app.models import Permission, Role
from app.rate_limit import RateLimiter
from app.service import AuthService
from app.session_store import SessionStore

settings = DEFAULT_SETTINGS

roles = {
    "reader": Role("reader", [Permission("read", "docs")]),
    "editor": Role("editor", [Permission("read", "docs"),
                              Permission("write", "docs/team-a")]),
    "admin": Role("admin", [Permission("*", "*")]),
}

service = AuthService(
    settings,
    SessionStore(settings.session_ttl_seconds),
    Authorizer(roles),
    RateLimiter(settings.max_failed_attempts,
                settings.lockout_seconds,
                settings.failure_window_seconds),
    users={"alice": "pw-alice", "bob": "pw-bob"},
)
service.set_user_roles("alice", ["reader"])
service.set_user_roles("bob", ["editor"])

app = create_app(service)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
