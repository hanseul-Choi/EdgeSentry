import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.core.state.memory_store import MemoryStateStore
from app.schemas.detection import DetectRequest, LoginResult


@pytest.mark.asyncio
async def test_record_and_get_ip_attempt_count():
    store = MemoryStateStore()
    base_time = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)

    # Record 3 attempts for IP 1.1.1.1
    for i in range(3):
        req = DetectRequest(
            ip="1.1.1.1",
            timestamp=base_time + timedelta(seconds=i * 10),
            account_id="user1",
        )
        await store.record_attempt(req)

    # Check at base_time + 30s with window 60s
    count = await store.get_ip_attempt_count("1.1.1.1", 60, base_time + timedelta(seconds=30))
    assert count == 3

    # Check window of 15s at base_time + 30s -> only events at 20s (i=2)
    count_short = await store.get_ip_attempt_count("1.1.1.1", 15, base_time + timedelta(seconds=30))
    assert count_short == 1

    # Check non-existent IP
    assert await store.get_ip_attempt_count("2.2.2.2", 60, base_time) == 0


@pytest.mark.asyncio
async def test_get_account_failure_count():
    store = MemoryStateStore()
    base_time = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)

    # Record 2 failures and 1 success for userA
    req1 = DetectRequest(
        ip="1.1.1.1",
        timestamp=base_time,
        account_id="userA",
        login_result=LoginResult.FAILURE,
    )
    req2 = DetectRequest(
        ip="1.1.1.1",
        timestamp=base_time + timedelta(seconds=5),
        account_id="userA",
        login_result=LoginResult.SUCCESS,
    )
    req3 = DetectRequest(
        ip="1.1.1.1",
        timestamp=base_time + timedelta(seconds=10),
        account_id="userA",
        login_result=LoginResult.FAILURE,
    )

    await store.record_attempt(req1)
    await store.record_attempt(req2)
    await store.record_attempt(req3)

    failures = await store.get_account_failure_count("userA", 60, base_time + timedelta(seconds=15))
    assert failures == 2


@pytest.mark.asyncio
async def test_get_ip_distinct_accounts():
    store = MemoryStateStore()
    base_time = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)

    # Record attempts from 1.1.1.1 to user1, user2, and user1 again
    for acct in ["user1", "user2", "user1", ""]:
        req = DetectRequest(
            ip="1.1.1.1",
            timestamp=base_time,
            account_id=acct if acct else None,
        )
        await store.record_attempt(req)

    distinct = await store.get_ip_distinct_accounts("1.1.1.1", 60, base_time)
    assert distinct == {"user1", "user2"}
    assert await store.get_ip_distinct_accounts_count("1.1.1.1", 60, base_time) == 2


@pytest.mark.asyncio
async def test_reset():
    store = MemoryStateStore()
    req = DetectRequest(ip="1.1.1.1", account_id="user1")
    await store.record_attempt(req)
    assert await store.get_ip_attempt_count("1.1.1.1", 60, req.timestamp) == 1

    await store.reset()
    assert await store.get_ip_attempt_count("1.1.1.1", 60, req.timestamp) == 0


@pytest.mark.asyncio
async def test_concurrent_access():
    store = MemoryStateStore()
    base_time = datetime.now(timezone.utc)

    async def worker(idx: int):
        req = DetectRequest(
            ip="9.9.9.9",
            account_id=f"user_{idx}",
            timestamp=base_time + timedelta(milliseconds=idx),
        )
        await store.record_attempt(req)

    await asyncio.gather(*(worker(i) for i in range(50)))
    count = await store.get_ip_attempt_count("9.9.9.9", 60, base_time + timedelta(seconds=1))
    assert count == 50
    distinct = await store.get_ip_distinct_accounts_count(
        "9.9.9.9", 60, base_time + timedelta(seconds=1)
    )
    assert distinct == 50
