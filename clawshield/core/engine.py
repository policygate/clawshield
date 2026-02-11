from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .condition import evaluate_condition, validate_condition
from .models import Fact, Finding

_REQUIRED_RULE_KEYS = {"id", "title", "severity", "confidence", "condition"}


@dataclass
class EvalResult:
    """Result of a policy evaluation: findings + any warnings produced."""
    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)


class PolicyLoadError(Exception):
    """Raised when a policy file is malformed."""


class PolicyEngine:
    """Loads YAML policy rules and evaluates them against collected facts."""

    def __init__(self, policy_path: Path) -> None:
        with open(policy_path) as f:
            policy = yaml.safe_load(f)

        if not isinstance(policy, dict):
            raise PolicyLoadError(f"{policy_path}: expected a YAML mapping at top level")

        rules = policy.get("rules", [])
        if not isinstance(rules, list):
            raise PolicyLoadError(f"{policy_path}: 'rules' must be a list")

        errors = _validate_rules(rules)
        if errors:
            joined = "\n  ".join(errors)
            raise PolicyLoadError(f"{policy_path}: policy validation failed:\n  {joined}")

        self._rules: list[dict] = rules

    def evaluate(self, facts: list[Fact]) -> EvalResult:
        fact_map, collisions = _build_fact_map(facts)
        warnings: list[str] = []
        if collisions:
            for key, sources in collisions.items():
                warnings.append(
                    f"fact '{key}' collected {len(sources)} times "
                    f"(sources: {', '.join(sources)}), using last value"
                )

        findings: list[Finding] = []

        for rule in self._rules:
            fact_keys = _extract_fact_keys(rule["condition"])

            if evaluate_condition(rule["condition"], fact_map):
                actions = rule.get("actions", {})
                recommended = [a["id"] for a in actions.get("recommended", [])]
                has_autofix = len(actions.get("autofix", [])) > 0
                triggered = [f for f in facts if f.key in fact_keys]

                findings.append(Finding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    severity=rule["severity"],
                    confidence=rule["confidence"],
                    evidence=triggered,
                    recommended_actions=recommended,
                    autofix_available=has_autofix,
                ))

        return EvalResult(findings=findings, warnings=warnings)


def _build_fact_map(facts: list[Fact]) -> tuple[dict, dict[str, list[str]]]:
    """Build a flat fact map. Return (map, collisions).

    collisions maps duplicate keys to their list of sources.
    """
    fact_map: dict = {}
    sources: dict[str, list[str]] = {}
    for f in facts:
        sources.setdefault(f.key, []).append(f.source)
        fact_map[f.key] = f.value
    collisions = {k: v for k, v in sources.items() if len(v) > 1}
    return fact_map, collisions


def _extract_fact_keys(condition: dict) -> set[str]:
    """Walk a condition tree and collect all referenced fact keys."""
    keys: set[str] = set()
    if "all" in condition:
        for c in condition["all"]:
            keys |= _extract_fact_keys(c)
    elif "any" in condition:
        for c in condition["any"]:
            keys |= _extract_fact_keys(c)
    elif "fact" in condition:
        keys.add(condition["fact"])
    return keys


def _validate_rules(rules: list) -> list[str]:
    """Validate that every rule has required keys and well-formed conditions."""
    errors: list[str] = []
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f"rules[{i}]: expected dict, got {type(rule).__name__}")
            continue
        missing = _REQUIRED_RULE_KEYS - rule.keys()
        if missing:
            errors.append(f"rules[{i}] (id={rule.get('id', '?')}): missing keys: {missing}")
        if "condition" in rule:
            cond_errors = validate_condition(rule["condition"])
            for err in cond_errors:
                errors.append(f"rules[{i}] (id={rule.get('id', '?')}): {err}")
    return errors
