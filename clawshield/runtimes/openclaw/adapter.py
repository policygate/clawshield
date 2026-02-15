from __future__ import annotations

import os
from pathlib import Path

_SEARCH_PATHS = [
    Path.home() / ".openclaw" / "openclaw.json",
    Path("/etc/openclaw/config.yaml"),
    Path.home() / ".openclaw" / "config.yaml",
    Path("openclaw.yaml"),
]


class OpenClawAdapter:
    """Read-only adapter for detecting and locating OpenClaw configuration."""

    def __init__(self, config_path: Path | None = None) -> None:
        self._explicit_path = config_path

    def detect(self) -> bool:
        return self._resolve_config() is not None

    def get_config_paths(self) -> list[Path]:
        resolved = self._resolve_config()
        return [resolved] if resolved else []

    def searched_locations(self) -> list[str]:
        """Return the list of paths that would be checked, in order."""
        locations: list[str] = []
        if self._explicit_path:
            locations.append(str(self._explicit_path))
        env_path = os.environ.get("OPENCLAW_CONFIG")
        if env_path:
            locations.append(f"$OPENCLAW_CONFIG ({env_path})")
        locations.extend(str(p) for p in _SEARCH_PATHS)
        return locations

    def _resolve_config(self) -> Path | None:
        if self._explicit_path and self._explicit_path.exists():
            return self._explicit_path

        env_path = os.environ.get("OPENCLAW_CONFIG")
        if env_path:
            p = Path(env_path)
            if p.exists():
                return p

        for p in _SEARCH_PATHS:
            if p.exists():
                return p

        return None
