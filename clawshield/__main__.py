"""Entry point: python -m clawshield [--json] [--fail-on LEVEL] <config>"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .core.engine import EvalResult, PolicyEngine, PolicyLoadError
from .runtimes.openclaw.adapter import OpenClawAdapter
from .scanners.docker import DockerScanner
from .scanners.openclaw.config import OpenClawConfigScanner
from .scanners.openclaw.permissions import FilePermissionsScanner
from .scanners.openclaw.secrets import SecretsLiteScanner

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="clawshield",
        description="Security audit for OpenClaw deployments",
    )
    parser.add_argument("config", nargs="?", help="Path to OpenClaw config file")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output findings as JSON")
    parser.add_argument("--policy", type=Path, help="Path to custom policy YAML")
    parser.add_argument(
        "--fail-on",
        choices=list(_SEVERITY_RANK),
        default="critical",
        help="Minimum severity that causes a non-zero exit code (default: critical)",
    )
    args = parser.parse_args()

    config_path = Path(args.config) if args.config else None
    policy_path = args.policy or Path(__file__).resolve().parent / "policies" / "vps_public.yaml"

    # Detect runtime
    adapter = OpenClawAdapter(config_path=config_path)
    if not adapter.detect():
        print("No OpenClaw configuration found.", file=sys.stderr)
        print(f"  searched: {', '.join(adapter.searched_locations())}", file=sys.stderr)
        print("Usage: python -m clawshield <path-to-openclaw-config.yaml>", file=sys.stderr)
        return 1

    # Load policy
    try:
        engine = PolicyEngine(policy_path)
    except PolicyLoadError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # Collect facts from all scanners
    warnings: list[str] = []

    config_scanner = OpenClawConfigScanner()
    facts = config_scanner.scan(adapter.get_config_paths())

    secrets_scanner = SecretsLiteScanner()
    facts.extend(secrets_scanner.scan(adapter.get_config_paths()))

    permissions_scanner = FilePermissionsScanner()
    facts.extend(permissions_scanner.scan(adapter.get_config_paths()))

    docker_scanner = DockerScanner()
    docker_facts, docker_warnings = docker_scanner.scan()
    facts.extend(docker_facts)
    warnings.extend(docker_warnings)

    if not facts:
        if args.json_output:
            empty = {
                "meta": {
                    "schema_version": "0.1",
                    "tool_version": __version__,
                    "policy_path": str(policy_path),
                },
                "findings": [],
                "facts": [],
            }
            print(json.dumps(empty, indent=2, default=str))
        else:
            print("No facts collected from configuration.")
        return 0

    # Evaluate policy
    result = engine.evaluate(facts)
    findings = result.findings
    all_warnings = warnings + result.warnings

    # Print warnings to stderr (all modes)
    for w in all_warnings:
        print(f"warning: {w}", file=sys.stderr)

    # Output
    if args.json_output:
        meta: dict = {"schema_version": "0.1", "tool_version": __version__, "policy_path": str(policy_path)}
        if all_warnings:
            meta["warnings"] = all_warnings
        output = {
            "meta": meta,
            "facts": [asdict(f) for f in facts],
            "findings": [asdict(f) for f in findings],
        }
        print(json.dumps(output, indent=2, default=str))
    elif not findings:
        print("Audit complete. No issues found for the checks performed.")
    else:
        for finding in findings:
            print(f"[{finding.severity.upper()}] {finding.rule_id}: {finding.title}")
            for ev in finding.evidence:
                print(f"  - {ev.key} = {ev.value}  ({ev.source})")
            if finding.recommended_actions:
                print(f"  recommended: {', '.join(finding.recommended_actions)}")
            if finding.autofix_available:
                print("  autofix: available")
            print()

    # Exit code based on --fail-on threshold
    threshold = _SEVERITY_RANK[args.fail_on]
    return 1 if any(_SEVERITY_RANK.get(f.severity, 0) >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
