from abc import ABC, abstractmethod
from typing import Optional

from app.config.settings import RuleConfig
from app.core.state.base import StateStore
from app.schemas.detection import DetectRequest, TriggeredRule


class BaseRule(ABC):
    """Base class for detection rules."""

    def __init__(self, rule_id: str, config: Optional[RuleConfig] = None):
        self.rule_id = rule_id
        self.config = config or RuleConfig()

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    @property
    def weight(self) -> int:
        return self.config.weight

    @property
    def window_seconds(self) -> int:
        return self.config.window_seconds

    @property
    def threshold(self) -> int:
        return self.config.threshold

    @abstractmethod
    async def evaluate(
        self, request: DetectRequest, state: StateStore
    ) -> Optional[TriggeredRule]:
        """Evaluate the incoming request against past state.

        Returns a TriggeredRule if an anomaly threshold is breached, else None.
        """
        pass
