import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from app.deps import get_service
from app.routes import router

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    svc = get_service()
    svc.roles.define_role("viewer", ["documents:read"])
    svc.roles.define_role("editor", ["documents:read", "documents:write"])
    svc.register_user("alice", "alice-pw", ["viewer"])
    svc.register_user("bob", "bob-pw", ["editor"])
    yield


app = FastAPI(title="session-authz", lifespan=lifespan)
app.include_router(router)


@app.get("/")
def read_root():
    return {"Hello": "World"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
