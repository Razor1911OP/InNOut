"""Lateral movement & exfil: GNN proxy + time-series anomaly."""

from __future__ import annotations

import math

import networkx as nx
import numpy as np

from narip.detection.base import isolation_scores
from narip.schemas.detection import LateralMovementResult
from narip.schemas.events import NetworkFlowEvent


class LateralMovementDetector:
    def __init__(self) -> None:
        self._models_used = ["gnn_graph_analysis", "time_series_anomaly"]

    def score(self, features: list[float], flows: list[NetworkFlowEvent] | None = None) -> LateralMovementResult:
        x = np.array([features], dtype=np.float64)
        ts = float(isolation_scores(x, seed=71)[0])
        gnn_risk = 0.0
        if flows:
            g = nx.DiGraph()
            for f in flows:
                g.add_edge(f.src_ip, f.dst_ip, weight=math.log1p(f.bytes_out))
            # risk ~ graph density * hub concentration
            if g.number_of_nodes() > 0:
                dc = nx.degree_centrality(g)
                gnn_risk = min(1.0, len(g.edges) / (len(g.nodes) + 1e-6) * max(dc.values(), default=0.0) * 2)
        breach = float(np.clip(0.55 * ts + 0.45 * gnn_risk, 0.0, 1.0))
        total_out = sum(f.bytes_out for f in flows) if flows else 0.0
        exfil_rate = float(max(0.0, total_out / 60.0))  # bytes/sec assuming 1-min window
        return LateralMovementResult(
            breach_likelihood=breach,
            exfiltration_rate_estimate_bytes_per_sec=exfil_rate,
            models_used=self._models_used,
            feature_vector=list(features),
        )
