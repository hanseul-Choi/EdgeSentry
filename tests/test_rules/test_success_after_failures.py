from datetime import datetime, timezone

import pytest

from app.config.settings import RuleConfig
from app.core.rules.success_after_failures import SuccessAfterFailuresRule
from app.core.state.memory_store import MemoryStateStore
from app.schemas.detection import DetectRequest, LoginResult


@pytest.fixture
def state_store():
    return MemoryStateStore()


@pytest.fixture
def rule():
    config = RuleConfig(
        enabled=True,
        weight=50,
        window_seconds=600,
        threshold=3,
    )
    return SuccessAfterFailuresRule(config=config)


@pytest.mark.asyncio
async def test_success_after_failures_triggers_when_threshold_met(rule, state_store):
    account = "target_user@example.com"

    # Record 3 prior failures
    for i in range(3):
        await state_store.record_attempt(
            DetectRequest(
                ip="198.51.100.10",
                account_id=account,
                login_result=LoginResult.FAILURE,
                timestamp=datetime(2026, 9, 20, 10, 1, i, tzinfo=timezone.utc),
            )
        )

    # Now a successful login attempt occurs
    success_request = DetectRequest(
        ip="198.51.100.99",
        account_id=account,
        login_result=LoginResult.SUCCESS,
        timestamp=datetime(2026, 9, 20, 10, 2, 0, tzinfo=timezone.utc),
    )

    result = await rule.evaluate(success_request, state_store, phase="report")
    assert result is not None
    assert result.rule_id == "success_after_failures"
    assert result.weight == 50
    assert "Login success after 3 failed attempts/600s" in result.detail


@pytest.mark.asyncio
async def test_success_after_failures_does_not_trigger_below_threshold(rule, state_store):
    account = "normal_user@example.com"

    # Only 2 failures recorded (threshold is 3)
    for i in range(2):
        await state_store.record_attempt(
            DetectRequest(
                ip="198.51.100.10",
                account_id=account,
                login_result=LoginResult.FAILURE,
                timestamp=datetime(2026, 9, 20, 10, 1, i, tzinfo=timezone.utc),
            )
        )

    success_request = DetectRequest(
        ip="198.51.100.10",
        account_id=account,
        login_result=LoginResult.SUCCESS,
        timestamp=datetime(2026, 9, 20, 10, 2, 0, tzinfo=timezone.utc),
    )

    result = await rule.evaluate(success_request, state_store, phase="report")
    assert result is None


@pytest.mark.asyncio
async def test_success_after_failures_does_not_trigger_on_failure(rule, state_store):
    account = "target_user@example.com"

    # 4 failures recorded
    for i in range(4):
        await state_store.record_attempt(
            DetectRequest(
                ip="198.51.100.10",
                account_id=account,
                login_result=LoginResult.FAILURE,
                timestamp=datetime(2026, 9, 20, 10, 1, i, tzinfo=timezone.utc),
            )
        )

    # Another failure should NOT trigger success_after_failures
    failure_request = DetectRequest(
        ip="198.51.100.10",
        account_id=account,
        login_result=LoginResult.FAILURE,
        timestamp=datetime(2026, 9, 20, 10, 2, 0, tzinfo=timezone.utc),
    )

    result = await rule.evaluate(failure_request, state_store, phase="report")
    assert result is None


@pytest.mark.asyncio
async def test_success_after_failures_skips_during_check_phase(rule, state_store):
    account = "target_user@example.com"

    for i in range(4):
        await state_store.record_attempt(
            DetectRequest(
                ip="198.51.100.10",
                account_id=account,
                login_result=LoginResult.FAILURE,
                timestamp=datetime(2026, 9, 20, 10, 1, i, tzinfo=timezone.utc),
            )
        )

    check_request = DetectRequest(
        ip="198.51.100.10",
        account_id=account,
        login_result=LoginResult.SUCCESS,
        timestamp=datetime(2026, 9, 20, 10, 2, 0, tzinfo=timezone.utc),
    )

    # During 'check' phase, this rule should not run
    result = await rule.evaluate(check_request, state_store, phase="check")
    assert result is None


@pytest.mark.asyncio
async def test_success_after_failures_missing_account(rule, state_store):
    request = DetectRequest(
        ip="198.51.100.10",
        account_id=None,
        login_result=LoginResult.SUCCESS,
    )
    result = await rule.evaluate(request, state_store, phase="report")
    assert result is None
