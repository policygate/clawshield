from __future__ import annotations

import json
import subprocess

from ..core.models import Fact


class DockerScanner:
    """Inspects running Docker containers for security-relevant facts.

    If Docker is not accessible, returns empty facts with a warning
    rather than raising an error.
    """

    name = "docker"

    def scan(self) -> tuple[list[Fact], list[str]]:
        """Scan running containers. Returns (facts, warnings)."""
        warnings: list[str] = []

        container_ids, error = _get_running_container_ids()
        if container_ids is None:
            warnings.append(f"Docker: {error}; skipping container inspection")
            return [], warnings

        if not container_ids:
            return [], warnings

        containers = _inspect_containers(container_ids)
        if containers is None:
            warnings.append("Failed to inspect running Docker containers")
            return [], warnings

        return parse_inspect_output(containers), warnings


def parse_inspect_output(containers: list[dict]) -> list[Fact]:
    """Parse docker inspect JSON and produce security-relevant facts.

    Evaluates across all containers:
    - docker.user: "root" if ANY container runs as root (empty user, "root", UID 0)
    - docker.privileged: True if ANY container has privileged mode
    """
    if not containers:
        return []

    root_names: list[str] = []
    privileged_names: list[str] = []
    all_names: list[str] = []

    for container in containers:
        cid = container.get("Id") or "unknown"
        name = container.get("Name") or cid[:12]
        name = name.lstrip("/")
        all_names.append(name)

        user = container.get("Config", {}).get("User", "")
        privileged = container.get("HostConfig", {}).get("Privileged", False)

        # Empty user, "root", or UID 0 all mean running as root
        if not user or user == "root" or user.split(":")[0] == "0":
            root_names.append(name)

        if privileged:
            privileged_names.append(name)

    facts: list[Fact] = []

    is_root = bool(root_names)
    facts.append(Fact(
        key="docker.user",
        value="root" if is_root else "non-root",
        source=f"docker_inspect:{_cap_names(root_names if is_root else all_names)}",
    ))

    is_privileged = bool(privileged_names)
    facts.append(Fact(
        key="docker.privileged",
        value=is_privileged,
        source=f"docker_inspect:{_cap_names(privileged_names if is_privileged else all_names)}",
    ))

    return facts


_SOURCE_NAME_LIMIT = 5


def _cap_names(names: list[str]) -> str:
    """Join container names, capping at _SOURCE_NAME_LIMIT with a count suffix."""
    if len(names) <= _SOURCE_NAME_LIMIT:
        return ",".join(names)
    shown = ",".join(names[:_SOURCE_NAME_LIMIT])
    return f"{shown} (+{len(names) - _SOURCE_NAME_LIMIT} more)"


def _get_running_container_ids() -> tuple[list[str] | None, str | None]:
    """Return (container_ids, None) on success, or (None, reason) on failure."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()[:200]
            return None, f"docker ps failed ({stderr or 'non-zero exit'})"
        return [cid for cid in result.stdout.strip().splitlines() if cid], None
    except FileNotFoundError:
        return None, "docker binary not found"
    except subprocess.TimeoutExpired:
        return None, "docker command timed out"
    except OSError as e:
        return None, f"OS error: {e}"


def _inspect_containers(container_ids: list[str]) -> list[dict] | None:
    """Run docker inspect and return parsed JSON, or None on failure."""
    try:
        result = subprocess.run(
            ["docker", "inspect", *container_ids],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None
