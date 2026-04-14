"""YAML SOAR-style playbooks: match risk + vendor context, emit actions (Splunk SOAR / XSOAR patterns)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from narip.config import Settings, get_settings


@dataclass
class Playbook:
    pb_id: str
    name: str
    enabled: bool
    match: dict[str, Any]
    steps: list[dict[str, Any]]


class PlaybookEngine:
    def __init__(self, settings: Settings | None = None) -> None:
        self._s = settings or get_settings()
        self._playbooks: list[Playbook] = []
        self._load()

    def _default_dir(self) -> Path:
        return Path(__file__).resolve().parent.parent / "data" / "playbooks"

    def _load(self) -> None:
        base = Path(self._s.playbook_dir) if self._s.playbook_dir else self._default_dir()
        self._playbooks = []
        if not base.is_dir():
            return
        for p in sorted(base.glob("*.yaml")):
            try:
                raw = yaml.safe_load(p.read_text(encoding="utf-8"))
                if not isinstance(raw, list):
                    raw = [raw]
                for doc in raw:
                    if not isinstance(doc, dict):
                        continue
                    pb_id = str(doc.get("id") or p.stem)
                    pb = Playbook(
                        pb_id=pb_id,
                        name=str(doc.get("name") or pb_id),
                        enabled=bool(doc.get("enabled", True)),
                        match=dict(doc.get("match") or {}),
                        steps=list(doc.get("steps") or []),
                    )
                    self._playbooks.append(pb)
            except (OSError, yaml.YAMLError):
                continue

    def reload(self) -> None:
        self._load()

    @property
    def playbooks(self) -> list[Playbook]:
        return [p for p in self._playbooks if p.enabled]

    @staticmethod
    def _matches(match: dict[str, Any], ctx: dict[str, Any]) -> bool:
        rs = int(ctx.get("risk_score") or 0)
        if "risk_score_gte" in match and rs < int(match["risk_score_gte"]):
            return False
        if "risk_score_lte" in match and rs > int(match["risk_score_lte"]):
            return False
        if "vendor_eq" in match and str(ctx.get("vendor")) != str(match["vendor_eq"]):
            return False
        if "tactic_in" in match:
            need = set(str(x) for x in match["tactic_in"])
            have = set(str(x) for x in (ctx.get("tactics") or []))
            if not (need & have):
                return False
        return True

    def evaluate(self, ctx: dict[str, Any]) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        for pb in self.playbooks:
            if self._matches(pb.match, ctx):
                for step in pb.steps:
                    actions.append({"playbook": pb.pb_id, **step})
        return actions
