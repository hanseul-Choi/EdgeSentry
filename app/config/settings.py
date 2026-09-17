from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel, Field


class RuleConfig(BaseModel):
    enabled: bool = True
    weight: int = Field(default=30, ge=0, le=100)
    window_seconds: int = Field(default=60, gt=0)
    threshold: int = Field(default=10, gt=0)
    params: Dict[str, Any] = Field(default_factory=dict)


class RiskThresholds(BaseModel):
    medium: int = Field(default=40, ge=0, le=100)
    high: int = Field(default=70, ge=0, le=100)


class Settings(BaseModel):
    risk_thresholds: RiskThresholds = Field(default_factory=RiskThresholds)
    rules: Dict[str, RuleConfig] = Field(default_factory=dict)

    @classmethod
    def load_from_yaml(cls, path: Optional[Path] = None) -> "Settings":
        if path is None:
            # Default to config/rules.yaml relative to this file
            path = Path(__file__).parent / "rules.yaml"

        if not path.exists():
            return cls()

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        return cls.model_validate(data)


# Global settings instance loaded once by default, or overridden in tests
def get_settings(config_path: Optional[str] = None) -> Settings:
    path = Path(config_path) if config_path else None
    return Settings.load_from_yaml(path)
