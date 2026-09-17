from datetime import datetime, timedelta, timezone

import pytest

from app.core.rules_engine import RulesEngine
from app.schemas.detection import DetectRequest, LoginResult, RiskLevel


@pytest.mark.asyncio
async def test_credential_stuffing_attack_scenario(rules_engine: RulesEngine):
    """An attacker performs automated credential stuffing from a single IP against many accounts."""
    base_time = datetime(2026, 9, 18, 11, 0, 0, tzinfo=timezone.utc)
    attacker_ip = "185.220.101.5"

    responses = []
    # Attacker tests 15 distinct accounts within 15 seconds (1 req/sec)
    for i in range(15):
        req = DetectRequest(
            ip=attacker_ip,
            account_id=f"target_victim_{i}@domain.com",
            login_result=LoginResult.FAILURE,
            timestamp=base_time + timedelta(seconds=i),
            user_agent="Python-requests/2.28.1",
        )
        res = await rules_engine.evaluate(req)
        responses.append(res)

    # First 4 attempts (0, 1, 2, 3): below fanout (5) and velocity (10) thresholds -> LOW risk
    for r in responses[:4]:
        assert r.score == 0
        assert r.risk_level == RiskLevel.LOW

    # 5th attempt (i=4): 5th distinct account -> triggers ip_account_fanout (weight 45) -> MEDIUM
    assert responses[4].score == 45
    assert responses[4].risk_level == RiskLevel.MEDIUM
    triggered_ids_4 = [t.rule_id for t in responses[4].triggered_rules]
    assert "ip_account_fanout" in triggered_ids_4
    assert "ip_high_velocity" not in triggered_ids_4

    # 10th attempt (i=9): triggers BOTH ip_account_fanout (45)
    # + ip_high_velocity (35) = 80 -> HIGH
    assert responses[9].score == 80
    assert responses[9].risk_level == RiskLevel.HIGH
    triggered_ids_9 = [t.rule_id for t in responses[9].triggered_rules]
    assert "ip_account_fanout" in triggered_ids_9
    assert "ip_high_velocity" in triggered_ids_9

    # 15th attempt (i=14): continuing attack remains HIGH risk
    assert responses[14].score == 80
    assert responses[14].risk_level == RiskLevel.HIGH
