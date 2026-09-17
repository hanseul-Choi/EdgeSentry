from datetime import datetime, timedelta, timezone

import pytest

from app.core.rules_engine import RulesEngine
from app.schemas.detection import DetectRequest, LoginResult, RiskLevel


@pytest.mark.asyncio
async def test_single_account_brute_force_attack(rules_engine: RulesEngine):
    """An attacker repeatedly guesses passwords for an admin account."""
    base_time = datetime(2026, 9, 18, 14, 0, 0, tzinfo=timezone.utc)
    ip = "192.0.2.1"
    target_account = "admin@company.com"

    responses = []
    # 10 failed login attempts in 10 seconds against admin@company.com
    for i in range(10):
        req = DetectRequest(
            ip=ip,
            account_id=target_account,
            login_result=LoginResult.FAILURE,
            timestamp=base_time + timedelta(seconds=i),
        )
        res = await rules_engine.evaluate(req)
        responses.append(res)

    # Attempts 1..4 (indices 0..3): below failure threshold (5) -> score 0
    for r in responses[:4]:
        assert r.score == 0
        assert r.risk_level == RiskLevel.LOW

    # 5th attempt (index 4): triggers account_high_failure (weight 40) -> MEDIUM
    assert responses[4].score == 40
    assert responses[4].risk_level == RiskLevel.MEDIUM
    assert any(t.rule_id == "account_high_failure" for t in responses[4].triggered_rules)

    # 10th attempt (index 9): triggers BOTH account_high_failure (40)
    # + ip_high_velocity (35) = 75 -> HIGH
    assert responses[9].score == 75
    assert responses[9].risk_level == RiskLevel.HIGH
    triggered_ids = [t.rule_id for t in responses[9].triggered_rules]
    assert "account_high_failure" in triggered_ids
    assert "ip_high_velocity" in triggered_ids
