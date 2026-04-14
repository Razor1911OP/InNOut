"""
Weekly retrain / feedback loop entrypoint (stub).

Wire to your feature store and label pipeline; outputs land in `ml/artifacts/`.
Regulatory posture: log dataset hashes, model versions, and approval gates (NIST/ISO/SOX).
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser(description="NARIP batch training / feedback")
    p.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "artifacts")
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "modules": [
            "phishing",
            "bec",
            "wire_fraud",
            "supply_chain",
            "otp_fraud",
            "account_takeover",
            "lateral_exfil",
        ],
        "note": "Replace with Kubeflow/MLflow/Airflow job; export ONNX/TorchScript as needed.",
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {args.out / 'manifest.json'}")


if __name__ == "__main__":
    main()
