import sys
from pathlib import Path

# repo: backend/narip as package
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from narip.schemas.events import EmailEvent
from narip.services.pipeline import DetectionPipeline


def test_unified_score_runs() -> None:
    pipe = DetectionPipeline()
    email = EmailEvent(
        message_id="1",
        sender="ceo@evil-lookalike.com",
        subject="URGENT wire transfer",
        body_text="Please wire funds immediately. Do not tell anyone. SWIFT details attached.",
        urls=["http://pay-now.tk/login"],
    )
    r = pipe.run_unified(email=email)
    assert 0 <= r.enterprise_risk_score <= 100
    assert len(r.breakdown) == 7
    assert len(r.shap_values) == len(r.shap_feature_names)
