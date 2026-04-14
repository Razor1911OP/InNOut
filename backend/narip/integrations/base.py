from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class IntegrationAdapter(ABC):
    name: str
    category: str  # ingestion | response

    @abstractmethod
    async def health(self) -> dict[str, Any]:
        ...

    @abstractmethod
    async def push_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Normalize external payload toward NARIP event schemas (stub)."""
        ...
