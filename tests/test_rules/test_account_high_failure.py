from datetime import datetime, timedelta, timezone

import pytest

from app.config.settings import RuleConfig
from app.core.rules.account_high_failure import AccountHighFailureRule
from app.core.state.memory_store import MemoryStateStore
from app.schemas.detection import DetectRequest, LoginResult


@pytest.mark.asyncio
async def test_account_high_failure_trigger_with_current_failure():
    # threshold 3, window 60s, weight 40
    config = RuleConfig(enabled=True, weight=40, window_seconds=60, threshold=3)
    rule = AccountHighFailureRule(config=config)
    store = MemoryStateStore()

    base_time = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)
    acct = "victim@example.com"

    # 2 previous failures
    for i in range(2):
        await store.record_attempt(
            DetectRequest(
                ip="10.0.0.1",
                account_id=acct,
                login_result=LoginResult.FAILURE,
                timestamp=base_time + timedelta(seconds=i * 5),
            )
        )

    # 3rd failure arrives
    req = DetectRequest(
        ip="10.0.0.2",
        account_id=acct,
        login_result=LoginResult.FAILURE,
        timestamp=base_time + timedelta(seconds=15),
    )
    result = await rule.evaluate(req, store)

    assert result is not None
    assert result.rule_id == "account_high_failure"
    assert result.weight == 40
    assert "3 failed attempts/60s for account" in result.detail


@pytest.mark.asyncio
async def test_account_high_failure_existing_threshold_breached():
    # If 3 failures already happened, a 4th attempt (even success) triggers rule
    # because account is compromised/under attack
    config = RuleConfig(enabled=True, weight=40, window_seconds=60, threshold=3)
    rule = AccountHighFailureRule(config=config)
    store = MemoryStateStore()

    base_time = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)
    acct = "victim@example.com"

    # 3 previous failures
    for i in range(3):
        await store.record_attempt(
            DetectRequest(
                ip="10.0.0.1",
                account_id=acct,
                login_result=LoginResult.FAILURE,
                timestamp=base_time + timedelta(seconds=i),
            )
        )

    # Subsequent success attempt
    req = DetectRequest(
        ip="10.0.0.1",
        account_id=acct,
        login_result=LoginResult.SUCCESS,
        timestamp=base_time + timedelta(seconds=10),
    )
    result = await rule.evaluate(req, store)

    assert result is not None
    assert result.rule_id == "account_high_failure"
    assert "3 failed attempts/60s for account" in result.detail


@pytest.mark.asyncio
async def test_account_high_failure_missing_account():
    config = RuleConfig(enabled=True, weight=40, window_seconds=60, threshold=2)
    rule = AccountHighFailureRule(config=config)
    store = MemoryStateStore()

    req = DetectRequest(ip="10.0.0.1", account_id=None, login_result=LoginResult.FAILURE)
    result = await rule.evaluate(req, store)
    assert result is None
