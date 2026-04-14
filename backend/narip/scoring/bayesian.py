"""Simple Bayesian update: posterior odds from prior and weighted likelihood proxy."""

from __future__ import annotations


def posterior_risk(prior: float, likelihood_risk: float) -> float:
    """Combine prior P(bad) with module likelihood (0–1) using odds update."""
    p = max(1e-6, min(1.0 - 1e-6, prior))
    l = max(1e-6, min(1.0 - 1e-6, likelihood_risk))
    odds = p / (1.0 - p)
    # treat l as Bayes factor toward compromise
    bf = l / (1.0 - l + 1e-9)
    post_odds = odds * bf
    post_p = post_odds / (1.0 + post_odds)
    return float(max(0.0, min(1.0, post_p)))
