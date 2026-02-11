"""Secrets-lite scanner: detects well-known API key names in the OpenClaw config directory.

Scope:
- .env file in the same directory as the OpenClaw config
- The OpenClaw config file itself
No recursion, no entropy analysis, no filesystem crawling.
"""
from __future__ import annotations

from pathlib import Path

from ...core.models import Fact

_KNOWN_KEY_NAMES = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "COHERE_API_KEY",
    "MISTRAL_API_KEY",
    "HUGGINGFACEHUB_API_TOKEN",
    "HF_TOKEN",
]

# Lowercase versions for case-insensitive matching in config files
_KNOWN_KEY_NAMES_LOWER = [k.lower() for k in _KNOWN_KEY_NAMES]


class SecretsLiteScanner:
    """Checks for well-known API key names in .env and config files."""

    name = "secrets_lite"

    def scan(self, config_paths: list[Path]) -> list[Fact]:
        facts: list[Fact] = []

        checked_dirs: set[Path] = set()
        for config_path in config_paths:
            config_dir = config_path.parent

            # Check .env once per directory
            if config_dir not in checked_dirs:
                checked_dirs.add(config_dir)
                env_path = config_dir / ".env"
                env_exists = env_path.is_file()

                facts.append(Fact(
                    key="secrets.env_file_present",
                    value=env_exists,
                    source=f"secrets_lite:{env_path}",
                ))

                facts.append(Fact(
                    key="secrets.api_key_in_env_file",
                    value=_scan_env_for_keys(env_path) if env_exists else False,
                    source=f"secrets_lite:{env_path}",
                ))

            # Check config file
            facts.append(Fact(
                key="secrets.api_key_in_config",
                value=_scan_file_for_key_names(config_path),
                source=f"secrets_lite:{config_path}",
            ))

        return facts


def _scan_env_for_keys(env_path: Path) -> bool:
    """Return True if .env contains any line starting with a known API key name."""
    try:
        text = env_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for key_name in _KNOWN_KEY_NAMES:
            if stripped.startswith(key_name + "="):
                return True
    return False


def _scan_file_for_key_names(file_path: Path) -> bool:
    """Return True if the file text contains any known API key name (case-insensitive)."""
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return False

    return any(key in text for key in _KNOWN_KEY_NAMES_LOWER)
