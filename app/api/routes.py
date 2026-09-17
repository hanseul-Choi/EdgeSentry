from fastapi import APIRouter, Depends

from app.core.rules_engine import RulesEngine
from app.schemas.detection import DetectRequest, DetectResponse

router = APIRouter(tags=["Detection"])

# Global or dependency-injected engine instance
_engine_instance: RulesEngine | None = None


def get_rules_engine() -> RulesEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = RulesEngine()
    return _engine_instance


def set_rules_engine(engine: RulesEngine) -> None:
    global _engine_instance
    _engine_instance = engine


@router.post("/detect", response_model=DetectResponse, summary="Evaluate authentication attempt")
async def detect_attempt(
    request: DetectRequest,
    engine: RulesEngine = Depends(get_rules_engine),
) -> DetectResponse:
    """Analyze incoming login attempt metadata and return risk score and triggered rules."""
    return await engine.evaluate(request)


@router.get("/health", summary="Health check endpoint")
async def health_check():
    return {"status": "ok", "version": "0.1.0"}
