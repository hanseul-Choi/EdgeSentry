import pytest


@pytest.mark.asyncio
async def test_login_check_does_not_mutate_state(async_client, state_store):
    """Calling /v1/login/check repeatedly should not record attempts or alter history."""
    test_ip = "192.0.2.100"
    account = "check_user@domain.com"

    for _ in range(5):
        resp = await async_client.post(
            "/v1/login/check",
            json={"ip": test_ip, "account_id": account},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "LOW"
        assert data["score"] == 0

    # Ensure state store still has 0 attempts recorded for this IP
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    attempts = await state_store.get_ip_attempt_count(test_ip, 60, now)
    assert attempts == 0


@pytest.mark.asyncio
async def test_login_flow_check_and_report(async_client, state_store):
    """End-to-end authentication flow: check -> password verification -> report."""
    test_ip = "198.51.100.77"
    account = "target@domain.com"

    # Step 1: Pre-auth check
    check_resp = await async_client.post(
        "/v1/login/check",
        json={"ip": test_ip, "account_id": account},
    )
    assert check_resp.status_code == 200
    assert check_resp.json()["risk_level"] == "LOW"

    # Step 2: Simulate 5 password failures reported by login server
    for i in range(5):
        report_resp = await async_client.post(
            "/v1/login/report",
            json={
                "ip": test_ip,
                "account_id": account,
                "login_result": "failure",
            },
        )
        assert report_resp.status_code == 200

    # After 5 failures, the 5th report response should have triggered account_high_failure
    last_report_data = report_resp.json()
    assert last_report_data["score"] >= 40
    triggered_ids = [r["rule_id"] for r in last_report_data["triggered_rules"]]
    assert "account_high_failure" in triggered_ids

    # Step 3: Now check endpoint should flag HIGH / MEDIUM risk to block
    # brute force attempt before password check!
    pre_auth_check_after_failures = await async_client.post(
        "/v1/login/check",
        json={"ip": test_ip, "account_id": account},
    )
    assert pre_auth_check_after_failures.status_code == 200
    check_data = pre_auth_check_after_failures.json()
    assert check_data["score"] >= 40
    check_triggered_ids = [r["rule_id"] for r in check_data["triggered_rules"]]
    assert "account_high_failure" in check_triggered_ids


@pytest.mark.asyncio
async def test_login_report_success_after_failures_triggers(async_client):
    """Report with success after 3 failures triggers success_after_failures rule."""
    test_ip = "198.51.100.88"
    account = "takeover_candidate@domain.com"

    for _ in range(3):
        await async_client.post(
            "/v1/login/report",
            json={
                "ip": test_ip,
                "account_id": account,
                "login_result": "failure",
            },
        )

    # Now report success
    success_resp = await async_client.post(
        "/v1/login/report",
        json={
            "ip": "203.0.113.5",  # Can even be from another IP
            "account_id": account,
            "login_result": "success",
        },
    )
    assert success_resp.status_code == 200
    data = success_resp.json()
    assert data["score"] >= 50
    triggered_ids = [r["rule_id"] for r in data["triggered_rules"]]
    assert "success_after_failures" in triggered_ids
