import pytest
from httpx import ASGITransport, AsyncClient

from app.api.routes import get_rules_engine, set_rules_engine
from app.config.settings import RiskThresholds, RuleConfig, Settings
from app.core.rules_engine import RulesEngine
from app.core.state.memory_store import MemoryStateStore
from app.main import app


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        risk_thresholds=RiskThresholds(medium=40, high=70),
        rules={
            "ip_high_velocity": RuleConfig(
                enabled=True, weight=35, window_seconds=60, threshold=10
            ),
            "account_high_failure": RuleConfig(
                enabled=True, weight=40, window_seconds=60, threshold=5
            ),
            "ip_account_fanout": RuleConfig(
                enabled=True, weight=45, window_seconds=60, threshold=5
            ),
        },
    )


@pytest.fixture
def state_store() -> MemoryStateStore:
    return MemoryStateStore(max_retention_seconds=3600)


@pytest.fixture
def rules_engine(test_settings: Settings, state_store: MemoryStateStore) -> RulesEngine:
    return RulesEngine(settings=test_settings, state_store=state_store)


@pytest.fixture
async def async_client(rules_engine: RulesEngine):
    app.dependency_overrides[get_rules_engine] = lambda: rules_engine
    set_rules_engine(rules_engine)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()
