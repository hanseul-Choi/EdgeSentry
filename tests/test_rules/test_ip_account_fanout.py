from datetime import datetime, timedelta, timezone

import pytest

from app.config.settings import RuleConfig
from app.core.rules.ip_account_fanout import IpAccountFanoutRule
from app.core.state.memory_store import MemoryStateStore
from app.schemas.detection import DetectRequest


@pytest.mark.asyncio
async def test_ip_account_fanout_trigger():
    # threshold 4 distinct accounts, window 60s, weight 45
    config = RuleConfig(enabled=True, weight=45, window_seconds=60, threshold=4)
    rule = IpAccountFanoutRule(config=config)
    store = MemoryStateStore()

    base_time = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)
    ip = "198.51.100.1"

    # Pre-populate 3 distinct accounts from same IP
    for i in range(3):
        await store.record_attempt(
            DetectRequest(
                ip=ip,
                account_id=f"user_{i}",
                timestamp=base_time + timedelta(seconds=i * 2),
            )
        )

    # 4th distinct account attempt arrives
    req = DetectRequest(
        ip=ip,
        account_id="user_3",
        timestamp=base_time + timedelta(seconds=10),
    )
    result = await rule.evaluate(req, store)

    assert result is not None
    assert result.rule_id == "ip_account_fanout"
    assert result.weight == 45
    assert "4 distinct accounts/60s from IP" in result.detail


@pytest.mark.asyncio
async def test_ip_account_fanout_duplicate_accounts_below_threshold():
    config = RuleConfig(enabled=True, weight=45, window_seconds=60, threshold=4)
    rule = IpAccountFanoutRule(config=config)
    store = MemoryStateStore()

    base_time = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)
    ip = "198.51.100.1"

    # Multiple attempts for the SAME account (not spraying)
    for _ in range(5):
        await store.record_attempt(
            DetectRequest(
                ip=ip,
                account_id="same_user",
                timestamp=base_time,
            )
        )

    req = DetectRequest(
        ip=ip,
        account_id="same_user",
        timestamp=base_time,
    )
    result = await rule.evaluate(req, store)
    assert result is None
