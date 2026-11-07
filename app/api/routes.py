from fastapi import APIRouter, Depends

from app.core.rules_engine import RulesEngine
from app.schemas.detection import (
    DetectRequest,
    DetectResponse,
    LoginCheckRequest,
    LoginReportRequest,
)

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


@router.post(
    "/login/check",
    response_model=DetectResponse,
    summary="Pre-auth check: evaluate risk before password verification",
)
async def login_check(
    request: LoginCheckRequest,
    engine: RulesEngine = Depends(get_rules_engine),
) -> DetectResponse:
    """Evaluate authentication risk prior to credential verification without persisting state."""
    return await engine.evaluate_check(request)


@router.post(
    "/login/report",
    response_model=DetectResponse,
    summary="Post-auth report: record outcome and evaluate result-based rules",
)
async def login_report(
    request: LoginReportRequest,
    engine: RulesEngine = Depends(get_rules_engine),
) -> DetectResponse:
    """Record authentication outcome and evaluate post-auth rules (e.g. success_after_failures)."""
    return await engine.evaluate_report(request)


@router.post(
    "/detect",
    response_model=DetectResponse,
    summary="Evaluate authentication attempt (legacy / backward compatibility)",
    deprecated=True,
)
async def detect_attempt(
    request: DetectRequest,
    engine: RulesEngine = Depends(get_rules_engine),
) -> DetectResponse:
    """Analyze incoming login attempt metadata and return risk score and triggered rules."""
    return await engine.evaluate(request)


@router.get("/health", summary="Health check endpoint")
async def health_check():
    return {"status": "ok", "version": "0.1.0"}
