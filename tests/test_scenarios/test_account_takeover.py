from datetime import datetime, timezone

import pytest

from app.core.rules_engine import RulesEngine
from app.core.state.memory_store import MemoryStateStore
from app.schemas.detection import LoginReportRequest, LoginResult, RiskLevel


@pytest.fixture
def engine():
    return RulesEngine(state_store=MemoryStateStore())


@pytest.mark.asyncio
async def test_account_takeover_after_repeated_failures(engine):
    victim = "victim_account@domain.com"
    attacker_ip = "198.51.100.50"

    # Step 1: Attacker attempts 3 times with wrong passwords
    for i in range(3):
        report_req = LoginReportRequest(
            ip=attacker_ip,
            account_id=victim,
            login_result=LoginResult.FAILURE,
            timestamp=datetime(2026, 9, 20, 12, 0, i * 10, tzinfo=timezone.utc),
        )
        await engine.evaluate_report(report_req)
        # Failure is recorded

    # Step 2: Attacker finally guesses or brute forces the correct password
    success_req = LoginReportRequest(
        ip=attacker_ip,
        account_id=victim,
        login_result=LoginResult.SUCCESS,
        timestamp=datetime(2026, 9, 20, 12, 1, 0, tzinfo=timezone.utc),
    )
    resp_success = await engine.evaluate_report(success_req)

    # Risk level must be at least MEDIUM (due to weight=50)
    assert resp_success.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)
    assert resp_success.score >= 50

    triggered_ids = [r.rule_id for r in resp_success.triggered_rules]
    assert "success_after_failures" in triggered_ids


@pytest.mark.asyncio
async def test_legitimate_direct_login_success(engine):
    user = "legit_user@domain.com"
    user_ip = "203.0.113.10"

    # Legitimate user logs in successfully without prior failures
    success_req = LoginReportRequest(
        ip=user_ip,
        account_id=user,
        login_result=LoginResult.SUCCESS,
        timestamp=datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc),
    )
    resp = await engine.evaluate_report(success_req)

    assert resp.risk_level == RiskLevel.LOW
    assert resp.score == 0
    assert len(resp.triggered_rules) == 0
