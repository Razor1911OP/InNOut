from typing import Any

from pydantic import BaseModel, Field


class EmailEvent(BaseModel):
    message_id: str
    sender: str
    reply_to: str | None = None
    subject: str = ""
    body_text: str = ""
    urls: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)


class TransactionEvent(BaseModel):
    txn_id: str
    amount: float
    currency: str = "USD"
    sender_account: str
    recipient_account: str
    initiated_at_iso: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class NetworkFlowEvent(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    bytes_out: int = 0
    process_name: str | None = None
    user_id: str | None = None


class OTPSessionEvent(BaseModel):
    session_id: str
    user_id: str
    keystroke_dwell_ms: list[float] = Field(default_factory=list)
    keystroke_flight_ms: list[float] = Field(default_factory=list)
    geo_lat: float | None = None
    geo_lon: float | None = None
    device_fingerprint: str = ""
    ip: str = ""


class AccountTelemetryEvent(BaseModel):
    user_id: str
    login_ip: str
    device_id: str
    resource_access: list[str] = Field(default_factory=list)
    privilege_level: int = 0
    timestamp_iso: str


class SupplyChainSignal(BaseModel):
    component_id: str
    version_old: str | None = None
    version_new: str | None = None
    vendor_egress_bytes_per_hour: float = 0.0
    baseline_egress_bytes_per_hour: float = 1.0
