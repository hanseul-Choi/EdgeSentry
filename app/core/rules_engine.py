from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from app.config.settings import RuleConfig, Settings, get_settings
from app.core.rules.account_high_failure import AccountHighFailureRule
from app.core.rules.base import BaseRule
from app.core.rules.ip_account_fanout import IpAccountFanoutRule
from app.core.rules.ip_high_velocity import IpHighVelocityRule
from app.core.state.base import StateStore
from app.core.state.memory_store import MemoryStateStore
from app.schemas.detection import DetectRequest, DetectResponse, RiskLevel, TriggeredRule


class RulesEngine:
    """Core evaluation engine that orchestrates rule execution, scoring, and state updates."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        state_store: Optional[StateStore] = None,
    ):
        self.settings = settings or get_settings()
        self.state_store: StateStore = state_store or MemoryStateStore()
        self.rules: Dict[str, BaseRule] = {}
        self._initialize_rules()

    def _initialize_rules(self) -> None:
        """Instantiate rules configured in settings."""
        rule_factories: Dict[str, Callable[[Optional[RuleConfig]], BaseRule]] = {
            "ip_high_velocity": IpHighVelocityRule,
            "account_high_failure": AccountHighFailureRule,
            "ip_account_fanout": IpAccountFanoutRule,
        }

        for rule_id, factory in rule_factories.items():
            rule_config = self.settings.rules.get(rule_id)
            self.rules[rule_id] = factory(rule_config)

    def register_rule(self, rule: BaseRule) -> None:
        """Register or overwrite an individual rule."""
        self.rules[rule.rule_id] = rule

    def calculate_risk_level(self, score: int) -> RiskLevel:
        """Determine RiskLevel based on configured thresholds."""
        if score >= self.settings.risk_thresholds.high:
            return RiskLevel.HIGH
        if score >= self.settings.risk_thresholds.medium:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    async def evaluate(self, request: DetectRequest) -> DetectResponse:
        """Evaluate an incoming authentication attempt.

        Flow:
        1. Query StateStore and execute all enabled rules.
        2. Collect triggered rules and aggregate score (clamped between 0 and 100).
        3. Determine risk level.
        4. Record attempt into StateStore to maintain historical context.
        5. Return DetectResponse.
        """
        triggered_rules: List[TriggeredRule] = []

        # 1. Execute rules
        for rule in self.rules.values():
            if rule.enabled:
                result = await rule.evaluate(request, self.state_store)
                if result is not None:
                    triggered_rules.append(result)

        # 2. Score aggregation
        raw_score = sum(r.weight for r in triggered_rules)
        score = min(100, max(0, raw_score))

        # 3. Categorize risk
        risk_level = self.calculate_risk_level(score)

        # 4. State update
        await self.state_store.record_attempt(request)

        # 5. Return response
        return DetectResponse(
            score=score,
            risk_level=risk_level,
            triggered_rules=triggered_rules,
            evaluated_at=datetime.now(timezone.utc),
        )
