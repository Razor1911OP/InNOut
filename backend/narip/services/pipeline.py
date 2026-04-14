"""Orchestrates feature extraction, seven detectors, and unified scoring."""

from __future__ import annotations

from narip.detection import (
    ATODetector,
    BECDetector,
    LateralMovementDetector,
    OTPFraudDetector,
    PhishingDetector,
    SupplyChainDetector,
    WireFraudDetector,
)
from narip.features.extraction import FeatureBundle, FeatureExtractor
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
from narip.schemas.risk import UnifiedRiskResponse
from narip.scoring.engine import ModuleOutputs, UnifiedRiskEngine


class DetectionPipeline:
    def __init__(self) -> None:
        self.features = FeatureExtractor()
        self.phishing_d = PhishingDetector()
        self.bec_d = BECDetector()
        self.wire_d = WireFraudDetector()
        self.supply_d = SupplyChainDetector()
        self.otp_d = OTPFraudDetector()
        self.ato_d = ATODetector()
        self.lateral_d = LateralMovementDetector()
        self.risk = UnifiedRiskEngine()

    def _default_email(self) -> EmailEvent:
        return EmailEvent(message_id="na", sender="user@internal.local", subject="", body_text="", urls=[])

    def _default_txn(self) -> TransactionEvent:
        return TransactionEvent(
            txn_id="na",
            amount=0.0,
            sender_account="na",
            recipient_account="na",
            initiated_at_iso="1970-01-01T00:00:00Z",
        )

    def _default_otp(self) -> OTPSessionEvent:
        return OTPSessionEvent(session_id="na", user_id="na")

    def _default_account(self) -> AccountTelemetryEvent:
        return AccountTelemetryEvent(user_id="na", login_ip="0.0.0.0", device_id="na", timestamp_iso="1970-01-01T00:00:00Z")

    def _default_supply(self) -> SupplyChainSignal:
        return SupplyChainSignal(component_id="na")

    def run_unified(
        self,
        email: EmailEvent | None = None,
        transaction: TransactionEvent | None = None,
        flows: list[NetworkFlowEvent] | None = None,
        otp: OTPSessionEvent | None = None,
        account: AccountTelemetryEvent | None = None,
        supply: SupplyChainSignal | None = None,
    ) -> UnifiedRiskResponse:
        email = email or self._default_email()
        transaction = transaction or self._default_txn()
        flows = flows or []
        otp = otp or self._default_otp()
        account = account or self._default_account()
        supply = supply or self._default_supply()

        bundle = FeatureBundle(
            phishing=self.features.phishing_from_email(email),
            bec=self.features.bec_from_email(email),
            wire=self.features.wire_from_transaction(transaction),
            supply_chain=self.features.supply_chain(supply),
            otp=self.features.otp_session(otp),
            ato=self.features.ato_telemetry(account),
            lateral=self.features.lateral_from_flows(flows),
        )
        self.features.build_unified(bundle)

        p: PhishingResult = self.phishing_d.score(bundle.phishing, email=email)
        b: BECResult = self.bec_d.score(bundle.bec)
        w: WireFraudResult = self.wire_d.score(
            bundle.wire,
            sender=transaction.sender_account,
            recipient=transaction.recipient_account,
        )
        s: SupplyChainResult = self.supply_d.score(bundle.supply_chain, signal=supply)
        o: OTPTakeoverResult = self.otp_d.score(bundle.otp)
        a: ATOResult = self.ato_d.score(bundle.ato)
        l: LateralMovementResult = self.lateral_d.score(bundle.lateral, flows=flows)

        m = ModuleOutputs(phishing=p, bec=b, wire=w, supply_chain=s, otp=o, ato=a, lateral=l)
        return self.risk.aggregate(m, bundle.unified_names, bundle.unified_vector)
