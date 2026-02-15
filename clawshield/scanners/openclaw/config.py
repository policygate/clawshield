from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from ...core.models import Fact


# OpenClaw bind modes that map to public exposure
_PUBLIC_BIND_MODES = {"0.0.0.0", "::", "lan", "public"}
_LOOPBACK_BIND_MODES = {"loopback", "localhost", "127.0.0.1", "::1"}

# Auth modes that count as "auth enabled"
_AUTH_ENABLED_MODES = {"token", "password", "trusted-proxy"}


class OpenClawConfigScanner:
    """Reads an OpenClaw config file and extracts security-relevant facts."""

    name = "openclaw_config"

    def scan(self, config_paths: list[Path]) -> list[Fact]:
        facts: list[Fact] = []
        for path in config_paths:
            config = _load_config(path)
            if config is None:
                continue

            source = f"openclaw_config:{path}"

            if _is_json_format(path, config):
                facts.extend(_extract_json_facts(config, source))
            else:
                facts.extend(_extract_yaml_facts(config, source))

        return facts


def _load_config(path: Path) -> dict | None:
    """Load a config file as a dict, auto-detecting JSON vs YAML."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None

    if path.suffix == ".json":
        try:
            return json.loads(text) or {}
        except json.JSONDecodeError:
            return None

    # Try JSON first (handles .json or files that happen to be JSON)
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    # Fall back to YAML
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return None


def _is_json_format(path: Path, config: dict) -> bool:
    """Detect whether this is an OpenClaw JSON config (openclaw.json style)."""
    if path.suffix == ".json":
        return True
    # Heuristic: JSON configs have a "gateway" top-level key
    return "gateway" in config


def _extract_json_facts(config: dict, source: str) -> list[Fact]:
    """Extract facts from OpenClaw's native JSON config (openclaw.json)."""
    facts: list[Fact] = []

    # gateway.bind → network.bind_address
    bind = _deep_get(config, "gateway.bind")
    if bind is not None:
        facts.append(Fact(
            key="network.bind_address",
            value=_normalize_json_bind(bind),
            source=source,
        ))

    # gateway.auth.mode → runtime.auth_enabled
    auth_mode = _deep_get(config, "gateway.auth.mode")
    if auth_mode is not None:
        facts.append(Fact(
            key="runtime.auth_enabled",
            value=auth_mode in _AUTH_ENABLED_MODES,
            source=source,
        ))
    else:
        # No auth configured at all — treat as disabled
        if "gateway" in config:
            facts.append(Fact(
                key="runtime.auth_enabled",
                value=False,
                source=source,
            ))

    return facts


def _extract_yaml_facts(config: dict, source: str) -> list[Fact]:
    """Extract facts from legacy YAML config format."""
    facts: list[Fact] = []

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


def _normalize_json_bind(value: Any) -> str:
    """Map OpenClaw bind modes to addresses for NET-001 evaluation.

    OpenClaw uses named modes like "loopback", "lan", etc.
    Map non-loopback modes to "0.0.0.0" so NET-001 can detect public exposure.
    """
    s = str(value).strip().lower()
    if s in _LOOPBACK_BIND_MODES:
        return "127.0.0.1"
    if s in _PUBLIC_BIND_MODES:
        return "0.0.0.0"
    # Unknown mode — pass through for manual inspection
    return s


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
