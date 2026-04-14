from fastapi import APIRouter, Depends

from narip.api.deps import get_pipeline
from narip.observability.metrics import Metrics
from narip.schemas.detection import (
    ATOResult,
    BECResult,
    LateralMovementResult,
    OTPTakeoverResult,
    PhishingResult,
    SupplyChainResult,
    WireFraudResult,
)
from narip.schemas.events import (
    AccountTelemetryEvent,
    EmailEvent,
    NetworkFlowEvent,
    OTPSessionEvent,
    SupplyChainSignal,
    TransactionEvent,
)
from narip.services.pipeline import DetectionPipeline

router = APIRouter(prefix="/v1/detect", tags=["detection-modules"])


@router.post("/phishing", response_model=PhishingResult)
def detect_phishing(email: EmailEvent, pipe: DetectionPipeline = Depends(get_pipeline)) -> PhishingResult:
    Metrics.module("phishing")
    f = pipe.features.phishing_from_email(email)
    return pipe.phishing_d.score(f, email=email)


@router.post("/bec", response_model=BECResult)
def detect_bec(email: EmailEvent, pipe: DetectionPipeline = Depends(get_pipeline)) -> BECResult:
    Metrics.module("bec")
    f = pipe.features.bec_from_email(email)
    return pipe.bec_d.score(f)


@router.post("/wire-fraud", response_model=WireFraudResult)
def detect_wire(txn: TransactionEvent, pipe: DetectionPipeline = Depends(get_pipeline)) -> WireFraudResult:
    Metrics.module("wire_fraud")
    f = pipe.features.wire_from_transaction(txn)
    return pipe.wire_d.score(f, sender=txn.sender_account, recipient=txn.recipient_account)


@router.post("/supply-chain", response_model=SupplyChainResult)
def detect_supply(signal: SupplyChainSignal, pipe: DetectionPipeline = Depends(get_pipeline)) -> SupplyChainResult:
    Metrics.module("supply_chain")
    f = pipe.features.supply_chain(signal)
    return pipe.supply_d.score(f, signal=signal)


@router.post("/otp-fraud", response_model=OTPTakeoverResult)
def detect_otp(session: OTPSessionEvent, pipe: DetectionPipeline = Depends(get_pipeline)) -> OTPTakeoverResult:
    Metrics.module("otp_fraud")
    f = pipe.features.otp_session(session)
    return pipe.otp_d.score(f)


@router.post("/account-takeover", response_model=ATOResult)
def detect_ato(acc: AccountTelemetryEvent, pipe: DetectionPipeline = Depends(get_pipeline)) -> ATOResult:
    Metrics.module("account_takeover")
    f = pipe.features.ato_telemetry(acc)
    return pipe.ato_d.score(f)


@router.post("/lateral-exfiltration", response_model=LateralMovementResult)
def detect_lateral(
    flows: list[NetworkFlowEvent],
    pipe: DetectionPipeline = Depends(get_pipeline),
) -> LateralMovementResult:
    Metrics.module("lateral_exfil")
    f = pipe.features.lateral_from_flows(flows)
    return pipe.lateral_d.score(f, flows=flows)
