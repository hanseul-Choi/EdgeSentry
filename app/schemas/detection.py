from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LoginResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"

    @classmethod
    def _missing_(cls, value: object):
        if isinstance(value, str):
            val_lower = value.strip().lower()
            if val_lower in ("success", "ok", "pass"):
                return cls.SUCCESS
            if val_lower in ("failure", "fail", "failed", "error"):
                return cls.FAILURE
        return None


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class DetectRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ip: str = Field(..., description="Client IP address", examples=["192.168.1.100"])
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="ISO8601 timestamp of the login attempt (defaults to current UTC time)",
    )
    account_id: Optional[str] = Field(
        default=None,
        description="Target account identifier or its hash",
        examples=["user@example.com"],
    )
    login_result: Optional[LoginResult] = Field(
        default=None,
        description="Outcome of authentication attempt (success or failure)",
    )
    user_agent: Optional[str] = Field(default=None, description="HTTP User-Agent header")
    endpoint: Optional[str] = Field(
        default=None,
        description="Target authentication endpoint, e.g., /api/v1/auth/login",
    )

    # Optional device & browser fingerprint fields
    device_fingerprint_hash: Optional[str] = Field(
        default=None, description="Client-side generated device fingerprint hash"
    )
    header_order_hash: Optional[str] = Field(
        default=None, description="Hash of HTTP header ordering"
    )

    # Optional session/cookie tracking
    session_id: Optional[str] = Field(default=None, description="Session identifier")
    cookie_id: Optional[str] = Field(default=None, description="Persistent tracking cookie ID")

    # Optional geo & network reputation
    geo_country: Optional[str] = Field(
        default=None, description="Two-letter ISO country code", examples=["KR", "US"]
    )
    geo_city: Optional[str] = Field(default=None, description="City name")
    asn: Optional[int] = Field(default=None, description="Autonomous System Number")
    is_known_proxy_vpn_dc: Optional[bool] = Field(
        default=None, description="Flag indicating whether IP belongs to known VPN/proxy/datacenter"
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_timezone_aware(cls, v):
        if v is None:
            return datetime.now(timezone.utc)
        if isinstance(v, str):
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v
        return v


class TriggeredRule(BaseModel):
    rule_id: str = Field(..., description="Unique identifier of triggered rule")
    weight: int = Field(..., description="Weight score contributed by this rule")
    detail: str = Field(..., description="Human-readable reason for triggering")


class DetectResponse(BaseModel):
    score: int = Field(..., ge=0, le=100, description="Aggregated risk score (0-100)")
    risk_level: RiskLevel = Field(..., description="Categorized risk level (LOW, MEDIUM, HIGH)")
    triggered_rules: List[TriggeredRule] = Field(
        default_factory=list, description="List of triggered rules and reasoning"
    )
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="ISO8601 evaluation timestamp",
    )
