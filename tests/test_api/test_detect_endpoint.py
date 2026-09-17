import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoints(async_client: AsyncClient):
    # Root health
    res_root = await async_client.get("/health")
    assert res_root.status_code == 200
    assert res_root.json()["status"] == "ok"

    # API v1 health
    res_v1 = await async_client.get("/v1/health")
    assert res_v1.status_code == 200
    assert res_v1.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_detect_endpoint_success(async_client: AsyncClient):
    payload = {
        "ip": "203.0.113.42",
        "account_id": "testuser@example.com",
        "login_result": "success",
        "user_agent": "Mozilla/5.0",
        "endpoint": "/v1/auth/login",
    }
    response = await async_client.post("/v1/detect", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["score"] == 0
    assert data["risk_level"] == "LOW"
    assert data["triggered_rules"] == []
    assert "evaluated_at" in data


@pytest.mark.asyncio
async def test_detect_endpoint_missing_ip(async_client: AsyncClient):
    payload = {
        "account_id": "user@example.com",
    }
    response = await async_client.post("/v1/detect", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_detect_endpoint_stateful_flow(async_client: AsyncClient):
    ip = "198.51.100.99"
    # Send 10 requests from same IP in quick succession
    for i in range(10):
        payload = {
            "ip": ip,
            "account_id": f"victim_{i}",
            "login_result": "failure",
        }
        res = await async_client.post("/v1/detect", json=payload)
        assert res.status_code == 200
        if i == 9:
            data = res.json()
            assert data["score"] >= 70
            assert data["risk_level"] == "HIGH"
            rule_ids = [r["rule_id"] for r in data["triggered_rules"]]
            assert "ip_high_velocity" in rule_ids
            assert "ip_account_fanout" in rule_ids
