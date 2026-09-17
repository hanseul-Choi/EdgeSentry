from typing import Optional

from app.config.settings import RuleConfig
from app.core.rules.base import BaseRule
from app.core.state.base import StateStore
from app.schemas.detection import DetectRequest, TriggeredRule


class IpHighVelocityRule(BaseRule):
    """Detects unusually high volume of login attempts from a single IP address."""

    def __init__(self, config: Optional[RuleConfig] = None):
        super().__init__(rule_id="ip_high_velocity", config=config)

    async def evaluate(
        self, request: DetectRequest, state: StateStore
    ) -> Optional[TriggeredRule]:
        if not self.enabled:
            return None

        # Previous attempts within window
        prev_attempts = await state.get_ip_attempt_count(
            ip=request.ip,
            window_seconds=self.window_seconds,
            reference_time=request.timestamp,
        )

        total_attempts = prev_attempts + 1

        if total_attempts >= self.threshold:
            return TriggeredRule(
                rule_id=self.rule_id,
                weight=self.weight,
                detail=f"{total_attempts} attempts/{self.window_seconds}s from IP",
            )

        return None
