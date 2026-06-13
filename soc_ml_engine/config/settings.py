"""Runtime configuration for Splunk telemetry collection and ML scoring."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    return float(value)


@dataclass(slots=True)
class SplunkConfig:
    scheme: str = "https"
    host: str = "localhost"
    port: int = 8089
    username: str | None = None
    password: str | None = None
    token: str | None = None
    verify_ssl: bool = False
    index: str = "main"
    earliest_time: str = "-24h"
    latest_time: str = "now"
    timeout_seconds: int = 30
    retry_count: int = 3
    page_size: int = 5000

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


@dataclass(slots=True)
class EngineConfig:
    splunk: SplunkConfig
    model_path: Path = Path("soc_ml_engine/outputs/isolation_forest_model.pkl")
    suspicious_output_path: Path = Path("soc_ml_engine/outputs/suspicious_events.json")
    splunk_hec_output_path: Path = Path("soc_ml_engine/outputs/splunk_hec_events.ndjson")
    window_minutes: int = 15
    contamination: float = 0.05
    random_state: int = 42
    output_min_score: float = 90.0
    max_events: int = 20000


def _load_json(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_config(path: str | Path | None = None) -> EngineConfig:
    """Load non-secret defaults from JSON and secrets from environment variables.

    Environment variables intentionally override file values so lab credentials can
    stay out of Git while common settings live in a reusable config file.
    """

    raw = _load_json(Path(path) if path else None)
    splunk_raw = raw.get("splunk", {})
    engine_raw = raw.get("engine", {})

    splunk = SplunkConfig(
        scheme=os.getenv("SPLUNK_SCHEME", splunk_raw.get("scheme", "https")),
        host=os.getenv("SPLUNK_HOST", splunk_raw.get("host", "localhost")),
        port=_env_int("SPLUNK_PORT", int(splunk_raw.get("port", 8089))),
        username=os.getenv("SPLUNK_USERNAME", splunk_raw.get("username")),
        password=os.getenv("SPLUNK_PASSWORD", splunk_raw.get("password")),
        token=os.getenv("SPLUNK_TOKEN", splunk_raw.get("token")),
        verify_ssl=_env_bool("SPLUNK_VERIFY_SSL", bool(splunk_raw.get("verify_ssl", False))),
        index=os.getenv("SPLUNK_INDEX", splunk_raw.get("index", "main")),
        earliest_time=os.getenv("SPLUNK_EARLIEST_TIME", splunk_raw.get("earliest_time", "-24h")),
        latest_time=os.getenv("SPLUNK_LATEST_TIME", splunk_raw.get("latest_time", "now")),
        timeout_seconds=_env_int("SPLUNK_TIMEOUT_SECONDS", int(splunk_raw.get("timeout_seconds", 30))),
        retry_count=_env_int("SPLUNK_RETRY_COUNT", int(splunk_raw.get("retry_count", 3))),
        page_size=_env_int("SPLUNK_PAGE_SIZE", int(splunk_raw.get("page_size", 5000))),
    )

    return EngineConfig(
        splunk=splunk,
        model_path=Path(os.getenv("SOC_ML_MODEL_PATH", engine_raw.get("model_path", "soc_ml_engine/outputs/isolation_forest_model.pkl"))),
        suspicious_output_path=Path(os.getenv("SOC_ML_OUTPUT_PATH", engine_raw.get("suspicious_output_path", "soc_ml_engine/outputs/suspicious_events.json"))),
        splunk_hec_output_path=Path(os.getenv("SOC_ML_HEC_OUTPUT_PATH", engine_raw.get("splunk_hec_output_path", "soc_ml_engine/outputs/splunk_hec_events.ndjson"))),
        window_minutes=_env_int("SOC_ML_WINDOW_MINUTES", int(engine_raw.get("window_minutes", 15))),
        contamination=_env_float("SOC_ML_CONTAMINATION", float(engine_raw.get("contamination", 0.05))),
        random_state=_env_int("SOC_ML_RANDOM_STATE", int(engine_raw.get("random_state", 42))),
        output_min_score=_env_float("SOC_ML_OUTPUT_MIN_SCORE", float(engine_raw.get("output_min_score", 90.0))),
        max_events=_env_int("SOC_ML_MAX_EVENTS", int(engine_raw.get("max_events", 20000))),
    )
