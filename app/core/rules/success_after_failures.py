from typing import Optional

from app.config.settings import RuleConfig
from app.core.rules.base import BaseRule
from app.core.state.base import StateStore
from app.schemas.detection import DetectRequest, LoginResult, TriggeredRule


class SuccessAfterFailuresRule(BaseRule):
    """Detects account takeover or brute force breakthrough where a login succeeds
    after repeated authentication failures targeting that account.
    """

    phases: set[str] = {"report"}

    def __init__(self, config: Optional[RuleConfig] = None):
        super().__init__(rule_id="success_after_failures", config=config)

    async def evaluate(
        self, request: DetectRequest, state: StateStore, phase: str = "report"
    ) -> Optional[TriggeredRule]:
        if not self.enabled or not self.is_applicable(phase):
            return None

        # Only triggers when login succeeds
        if request.login_result != LoginResult.SUCCESS:
            return None

        # Account ID must be provided
        if not request.account_id or not request.account_id.strip():
            return None

        prev_failures = await state.get_account_failure_count(
            account_id=request.account_id,
            window_seconds=self.window_seconds,
            reference_time=request.timestamp,
        )

        if prev_failures >= self.threshold:
            return TriggeredRule(
                rule_id=self.rule_id,
                weight=self.weight,
                detail=(
                    f"Login success after {prev_failures} failed attempts/"
                    f"{self.window_seconds}s for account"
                ),
            )

        return None
