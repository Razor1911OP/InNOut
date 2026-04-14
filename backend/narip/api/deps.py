from narip.automation.cases import CaseStore
from narip.automation.playbooks import PlaybookEngine
from narip.config import Settings, get_settings as _get_settings
from narip.pubsub.bus import IncidentBroker
from narip.security.correlator import HostCorrelator
from narip.services.ingest_orchestrator import IngestOrchestrator
from narip.services.pipeline import DetectionPipeline
from narip.services.workforce_service import WorkforceService
from narip.threat_intel.ioc_store import IOCStore

_pipeline: DetectionPipeline | None = None
_broker: IncidentBroker | None = None
_ioc: IOCStore | None = None
_correlator: HostCorrelator | None = None
_cases: CaseStore | None = None
_playbooks: PlaybookEngine | None = None
_orch: IngestOrchestrator | None = None
_workforce: WorkforceService | None = None


def get_settings() -> Settings:
    return _get_settings()


def get_pipeline() -> DetectionPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = DetectionPipeline()
    return _pipeline


def get_broker() -> IncidentBroker:
    global _broker
    if _broker is None:
        _broker = IncidentBroker()
    return _broker


def get_ioc_store() -> IOCStore:
    global _ioc
    if _ioc is None:
        _ioc = IOCStore()
        _ioc.seed_defaults()
    return _ioc


def get_correlator() -> HostCorrelator:
    global _correlator
    if _correlator is None:
        _correlator = HostCorrelator()
    return _correlator


def get_case_store() -> CaseStore:
    global _cases
    if _cases is None:
        _cases = CaseStore()
    return _cases


def get_playbook_engine() -> PlaybookEngine:
    global _playbooks
    if _playbooks is None:
        _playbooks = PlaybookEngine()
    return _playbooks


def get_orchestrator() -> IngestOrchestrator:
    global _orch
    if _orch is None:
        _orch = IngestOrchestrator(
            get_pipeline(),
            get_ioc_store(),
            get_correlator(),
            get_playbook_engine(),
            get_case_store(),
            get_broker(),
        )
    return _orch


def get_workforce_service() -> WorkforceService:
    global _workforce
    if _workforce is None:
        _workforce = WorkforceService(get_pipeline())
    return _workforce
