from datetime import datetime, timedelta, timezone

import pytest

from app.config.settings import RuleConfig
from app.core.rules.ip_high_velocity import IpHighVelocityRule
from app.core.state.memory_store import MemoryStateStore
from app.schemas.detection import DetectRequest


@pytest.mark.asyncio
async def test_ip_high_velocity_trigger():
    # threshold 5, window 60s, weight 35
    config = RuleConfig(enabled=True, weight=35, window_seconds=60, threshold=5)
    rule = IpHighVelocityRule(config=config)
    store = MemoryStateStore()

    base_time = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)
    ip = "192.168.1.50"

    # Pre-populate 4 attempts in store
    for i in range(4):
        await store.record_attempt(
            DetectRequest(ip=ip, timestamp=base_time + timedelta(seconds=i))
        )

    # 5th attempt arrives
    req = DetectRequest(ip=ip, timestamp=base_time + timedelta(seconds=4))
    result = await rule.evaluate(req, store)

    assert result is not None
    assert result.rule_id == "ip_high_velocity"
    assert result.weight == 35
    assert "5 attempts/60s from IP" in result.detail


@pytest.mark.asyncio
async def test_ip_high_velocity_below_threshold():
    config = RuleConfig(enabled=True, weight=35, window_seconds=60, threshold=5)
    rule = IpHighVelocityRule(config=config)
    store = MemoryStateStore()

    base_time = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)
    ip = "192.168.1.50"

    # Only 2 previous attempts
    for i in range(2):
        await store.record_attempt(
            DetectRequest(ip=ip, timestamp=base_time + timedelta(seconds=i))
        )

    # 3rd attempt arrives -> total 3 < 5
    req = DetectRequest(ip=ip, timestamp=base_time + timedelta(seconds=2))
    result = await rule.evaluate(req, store)
    assert result is None


@pytest.mark.asyncio
async def test_ip_high_velocity_disabled():
    config = RuleConfig(enabled=False, weight=35, window_seconds=60, threshold=1)
    rule = IpHighVelocityRule(config=config)
    store = MemoryStateStore()

    req = DetectRequest(ip="1.1.1.1")
    result = await rule.evaluate(req, store)
    assert result is None
