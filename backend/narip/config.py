from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NARIP_", env_file=".env", extra="ignore")

    app_name: str = "NARIP API"
    debug: bool = False
    redis_url: str | None = None

    # Module weights for unified score (sum need not be 1; normalized in engine)
    weight_phishing: float = 0.14
    weight_bec: float = 0.14
    weight_wire: float = 0.15
    weight_supply_chain: float = 0.12
    weight_otp: float = 0.13
    weight_ato: float = 0.14
    weight_lateral: float = 0.18

    # Bayesian prior for enterprise risk (0–1)
    risk_prior: float = 0.05

    # Target SLOs (documented; used in metrics/alerts)
    slo_latency_ms: float = 500.0
    slo_events_per_sec: float = 10000.0

    # Splunk HEC (optional; if set, /v1/ingest/splunk/hec requires Authorization: Splunk <token>)
    splunk_hec_token: str | None = None

    # Playbooks directory (YAML); defaults to package data/playbooks
    playbook_dir: str | None = None

    # CrowdStrike Falcon Stream API verification secret (optional)
    falcon_stream_verification_secret: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
