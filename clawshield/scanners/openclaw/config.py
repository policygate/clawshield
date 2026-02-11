from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ...core.models import Fact


class OpenClawConfigScanner:
    """Reads an OpenClaw config file and extracts security-relevant facts."""

    name = "openclaw_config"

    def scan(self, config_paths: list[Path]) -> list[Fact]:
        facts: list[Fact] = []
        for path in config_paths:
            with open(path) as f:
                config = yaml.safe_load(f) or {}

            source = f"openclaw_config:{path}"

            bind = _deep_get(config, "server.bind_address")
            if bind is not None:
                facts.append(Fact(
                    key="network.bind_address",
                    value=_normalize_bind_address(bind),
                    source=source,
                ))

            auth = _deep_get(config, "auth.enabled")
            if auth is not None:
                facts.append(Fact(
                    key="runtime.auth_enabled",
                    value=_normalize_bool(auth),
                    source=source,
                ))

        return facts


def _normalize_bind_address(value: Any) -> str:
    """Coerce bind address to a stripped string."""
    return str(value).strip()


def _normalize_bool(value: Any) -> bool | Any:
    """Coerce string booleans to actual bools. Pass through non-strings unchanged."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes"):
            return True
        if lowered in ("false", "0", "no"):
            return False
    return value


def _deep_get(d: dict, dotted_key: str) -> Any | None:
    """Traverse nested dicts using a dotted key path."""
    current: Any = d
    for k in dotted_key.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(k)
        if current is None:
            return None
    return current
