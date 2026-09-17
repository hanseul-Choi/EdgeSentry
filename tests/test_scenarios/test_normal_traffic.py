from datetime import datetime, timedelta, timezone

import pytest

from app.core.rules_engine import RulesEngine
from app.schemas.detection import DetectRequest, LoginResult, RiskLevel


@pytest.mark.asyncio
async def test_normal_legitimate_traffic(rules_engine: RulesEngine):
    """Normal legitimate users logging into their individual accounts at realistic intervals."""
    base_time = datetime(2026, 9, 18, 9, 0, 0, tzinfo=timezone.utc)

    # 3 legitimate users logging in from different home/office IPs
    users = [
        ("203.0.113.10", "alice@example.com"),
        ("203.0.113.20", "bob@example.com"),
        ("203.0.113.30", "charlie@example.com"),
    ]

    for i, (ip, account) in enumerate(users):
        req = DetectRequest(
            ip=ip,
            account_id=account,
            login_result=LoginResult.SUCCESS,
            timestamp=base_time + timedelta(seconds=i * 5),
        )
        response = await rules_engine.evaluate(req)

        assert response.score == 0
        assert response.risk_level == RiskLevel.LOW
        assert len(response.triggered_rules) == 0


@pytest.mark.asyncio
async def test_normal_occasional_user_typo(rules_engine: RulesEngine):
    """User makes a typo (single failure) then enters correct password (success)."""
    base_time = datetime(2026, 9, 18, 9, 0, 0, tzinfo=timezone.utc)
    ip = "203.0.113.50"
    account = "david@example.com"

    # Attempt 1: password typo
    req1 = DetectRequest(
        ip=ip,
        account_id=account,
        login_result=LoginResult.FAILURE,
        timestamp=base_time,
    )
    res1 = await rules_engine.evaluate(req1)
    assert res1.score == 0
    assert res1.risk_level == RiskLevel.LOW

    # Attempt 2: successful login 5 seconds later
    req2 = DetectRequest(
        ip=ip,
        account_id=account,
        login_result=LoginResult.SUCCESS,
        timestamp=base_time + timedelta(seconds=5),
    )
    res2 = await rules_engine.evaluate(req2)
    assert res2.score == 0
    assert res2.risk_level == RiskLevel.LOW
    assert len(res2.triggered_rules) == 0
