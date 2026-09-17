from abc import ABC, abstractmethod
from datetime import datetime
from typing import Set

from app.schemas.detection import DetectRequest


class StateStore(ABC):
    """Abstract interface for storing and querying authentication attempt history."""

    @abstractmethod
    async def record_attempt(self, event: DetectRequest) -> None:
        """Record an authentication attempt event."""
        pass

    @abstractmethod
    async def get_ip_attempt_count(
        self, ip: str, window_seconds: int, reference_time: datetime
    ) -> int:
        """Get total number of previous attempts from this IP within the time window."""
        pass

    @abstractmethod
    async def get_account_failure_count(
        self, account_id: str, window_seconds: int, reference_time: datetime
    ) -> int:
        """Get total number of previous failed attempts for this account within the time window."""
        pass

    @abstractmethod
    async def get_ip_distinct_accounts(
        self, ip: str, window_seconds: int, reference_time: datetime
    ) -> Set[str]:
        """Get set of unique account IDs targeted from this IP within the time window."""
        pass

    @abstractmethod
    async def get_ip_distinct_accounts_count(
        self, ip: str, window_seconds: int, reference_time: datetime
    ) -> int:
        """Get number of unique account IDs targeted from this IP within the time window."""
        pass

    @abstractmethod
    async def reset(self) -> None:
        """Clear all stored state (primarily used in testing and maintenance)."""
        pass
