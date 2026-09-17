from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router as api_router
from app.api.routes import set_rules_engine
from app.core.rules_engine import RulesEngine


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure rules engine and in-memory state store are initialized
    engine = RulesEngine()
    set_rules_engine(engine)
    yield
    # Shutdown cleanup if needed
    await engine.state_store.reset()


def create_app() -> FastAPI:
    application = FastAPI(
        title="EdgeSentry — Credential Stuffing Detector",
        description="Real-time Credential Stuffing & Automated Abuse Detection Engine",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API routers
    application.include_router(api_router, prefix="/v1")

    # Global healthcheck
    @application.get("/health", tags=["System"])
    async def root_health():
        return {"status": "ok", "service": "EdgeSentry"}

    return application


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
