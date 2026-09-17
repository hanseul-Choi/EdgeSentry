from typing import Optional

from app.config.settings import RuleConfig
from app.core.rules.base import BaseRule
from app.core.state.base import StateStore
from app.schemas.detection import DetectRequest, LoginResult, TriggeredRule


class AccountHighFailureRule(BaseRule):
    """Detects repeated authentication failures targeting a specific account."""

    def __init__(self, config: Optional[RuleConfig] = None):
        super().__init__(rule_id="account_high_failure", config=config)

    async def evaluate(
        self, request: DetectRequest, state: StateStore
    ) -> Optional[TriggeredRule]:
        if not self.enabled:
            return None

        # If account_id is missing, this rule cannot be evaluated
        if not request.account_id or not request.account_id.strip():
            return None

        prev_failures = await state.get_account_failure_count(
            account_id=request.account_id,
            window_seconds=self.window_seconds,
            reference_time=request.timestamp,
        )

        is_current_failure = request.login_result == LoginResult.FAILURE
        total_failures = prev_failures + (1 if is_current_failure else 0)

        if total_failures >= self.threshold:
            return TriggeredRule(
                rule_id=self.rule_id,
                weight=self.weight,
                detail=f"{total_failures} failed attempts/{self.window_seconds}s for account",
            )

        return None
