import asyncio
from collections import defaultdict, deque
from datetime import datetime
from typing import Deque, Dict, Optional, Set, Tuple

from app.core.state.base import StateStore
from app.schemas.detection import DetectRequest, LoginResult


class MemoryStateStore(StateStore):
    """Thread-safe in-memory sliding window state store."""

    def __init__(self, max_retention_seconds: int = 3600):
        self.max_retention_seconds = max_retention_seconds
        self._lock = asyncio.Lock()
        # ip -> deque of (timestamp_epoch, account_id, login_result)
        self._ip_events: Dict[str, Deque[Tuple[float, Optional[str], Optional[str]]]] = defaultdict(
            deque
        )
        # account_id -> deque of (timestamp_epoch, login_result)
        self._account_events: Dict[str, Deque[Tuple[float, Optional[str]]]] = defaultdict(deque)

    async def record_attempt(self, event: DetectRequest) -> None:
        async with self._lock:
            ts = event.timestamp.timestamp()
            res_val = event.login_result.value if event.login_result else None

            # Prune and append IP event
            ip_q = self._ip_events[event.ip]
            self._prune_deque(ip_q, ts - self.max_retention_seconds)
            ip_q.append((ts, event.account_id, res_val))

            # Prune and append Account event if account_id is provided
            if event.account_id:
                acct_q = self._account_events[event.account_id]
                self._prune_deque(acct_q, ts - self.max_retention_seconds)
                acct_q.append((ts, res_val))

    async def get_ip_attempt_count(
        self, ip: str, window_seconds: int, reference_time: datetime
    ) -> int:
        async with self._lock:
            if ip not in self._ip_events:
                return 0
            ref_ts = reference_time.timestamp()
            cutoff = ref_ts - window_seconds
            ip_q = self._ip_events[ip]
            self._prune_deque(ip_q, ref_ts - self.max_retention_seconds)

            count = sum(1 for (ts, _, _) in ip_q if cutoff <= ts <= ref_ts)
            return count

    async def get_account_failure_count(
        self, account_id: str, window_seconds: int, reference_time: datetime
    ) -> int:
        if not account_id:
            return 0
        async with self._lock:
            if account_id not in self._account_events:
                return 0
            ref_ts = reference_time.timestamp()
            cutoff = ref_ts - window_seconds
            acct_q = self._account_events[account_id]
            self._prune_deque(acct_q, ref_ts - self.max_retention_seconds)

            count = sum(
                1
                for (ts, res) in acct_q
                if cutoff <= ts <= ref_ts and res == LoginResult.FAILURE.value
            )
            return count

    async def get_ip_distinct_accounts(
        self, ip: str, window_seconds: int, reference_time: datetime
    ) -> Set[str]:
        async with self._lock:
            if ip not in self._ip_events:
                return set()
            ref_ts = reference_time.timestamp()
            cutoff = ref_ts - window_seconds
            ip_q = self._ip_events[ip]
            self._prune_deque(ip_q, ref_ts - self.max_retention_seconds)

            unique_accounts = {
                acct_id
                for (ts, acct_id, _) in ip_q
                if cutoff <= ts <= ref_ts and acct_id is not None and acct_id.strip() != ""
            }
            return unique_accounts

    async def get_ip_distinct_accounts_count(
        self, ip: str, window_seconds: int, reference_time: datetime
    ) -> int:
        accounts = await self.get_ip_distinct_accounts(ip, window_seconds, reference_time)
        return len(accounts)

    async def reset(self) -> None:
        async with self._lock:
            self._ip_events.clear()
            self._account_events.clear()

    @staticmethod
    def _prune_deque(q: Deque, cutoff: float) -> None:
        while q and q[0][0] < cutoff:
            q.popleft()
