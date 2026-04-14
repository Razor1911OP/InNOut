from __future__ import annotations

import time
from collections.abc import Callable
from functools import wraps

from prometheus_client import Counter, Histogram

INGEST_TOTAL = Counter(
    "narip_ingest_total",
    "Falcon/Splunk ingest outcomes",
    ["vendor", "result"],
)

REQUEST_LATENCY = Histogram(
    "narip_request_latency_seconds",
    "End-to-end handler latency",
    ["handler"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
EVENTS_SCORED = Counter("narip_events_scored_total", "Total events scored", ["result"])
MODULE_INVOCATIONS = Counter("narip_module_invocations_total", "Per detection module", ["module"])


class Metrics:
    @staticmethod
    def ingest(vendor: str, ok: bool) -> None:
        INGEST_TOTAL.labels(vendor=vendor, result="ok" if ok else "error").inc()

    @staticmethod
    def observe_latency(handler: str, seconds: float) -> None:
        REQUEST_LATENCY.labels(handler=handler).observe(seconds)

    @staticmethod
    def event_result(ok: bool) -> None:
        EVENTS_SCORED.labels(result="ok" if ok else "error").inc()

    @staticmethod
    def module(name: str) -> None:
        MODULE_INVOCATIONS.labels(module=name).inc()


def timed(handler_name: str) -> Callable[[Callable[..., object]], Callable[..., object]]:
    def deco(fn: Callable[..., object]) -> Callable[..., object]:
        @wraps(fn)
        async def awrapper(*args, **kwargs):
            t0 = time.perf_counter()
            try:
                return await fn(*args, **kwargs)
            finally:
                Metrics.observe_latency(handler_name, time.perf_counter() - t0)

        @wraps(fn)
        def swrapper(*args, **kwargs):
            t0 = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                Metrics.observe_latency(handler_name, time.perf_counter() - t0)

        import asyncio

        if asyncio.iscoroutinefunction(fn):
            return awrapper
        return swrapper

    return deco
