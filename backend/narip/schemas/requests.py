from pydantic import BaseModel, Field

from narip.schemas.events import (
    AccountTelemetryEvent,
    EmailEvent,
    NetworkFlowEvent,
    OTPSessionEvent,
    SupplyChainSignal,
    TransactionEvent,
)


class UnifiedScoreRequest(BaseModel):
    """Optional payloads per domain; omitted sections use neutral baselines."""

    email: EmailEvent | None = None
    transaction: TransactionEvent | None = None
    flows: list[NetworkFlowEvent] = Field(default_factory=list)
    otp: OTPSessionEvent | None = None
    account: AccountTelemetryEvent | None = None
    supply: SupplyChainSignal | None = None


class UnifiedScoreBatchRequest(BaseModel):
    """Batch unified scoring over REST (replaces WebSocket streaming for clients)."""

    items: list[UnifiedScoreRequest] = Field(default_factory=list, max_length=500)
