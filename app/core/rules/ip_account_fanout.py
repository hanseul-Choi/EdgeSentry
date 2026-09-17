from typing import Optional

from app.config.settings import RuleConfig
from app.core.rules.base import BaseRule
from app.core.state.base import StateStore
from app.schemas.detection import DetectRequest, TriggeredRule


class IpAccountFanoutRule(BaseRule):
    """Detects password spraying / credential stuffing where a single IP
    targets many different accounts.
    """

    def __init__(self, config: Optional[RuleConfig] = None):
        super().__init__(rule_id="ip_account_fanout", config=config)

    async def evaluate(
        self, request: DetectRequest, state: StateStore
    ) -> Optional[TriggeredRule]:
        if not self.enabled:
            return None

        distinct_accounts = await state.get_ip_distinct_accounts(
            ip=request.ip,
            window_seconds=self.window_seconds,
            reference_time=request.timestamp,
        )

        all_accounts = set(distinct_accounts)
        if request.account_id and request.account_id.strip():
            all_accounts.add(request.account_id.strip())

        total_accounts = len(all_accounts)

        if total_accounts >= self.threshold:
            return TriggeredRule(
                rule_id=self.rule_id,
                weight=self.weight,
                detail=f"{total_accounts} distinct accounts/{self.window_seconds}s from IP",
            )

        return None
