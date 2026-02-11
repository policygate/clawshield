from __future__ import annotations

from typing import Any

_VALID_OPS = {"eq", "in"}


class PolicyValidationError(Exception):
    """Raised when a policy condition node has an invalid shape."""


def validate_condition(condition: dict) -> list[str]:
    """Return a list of error strings if the condition tree is malformed."""
    errors: list[str] = []
    _validate_node(condition, errors, path="condition")
    return errors


def _validate_node(node: dict, errors: list[str], path: str) -> None:
    if not isinstance(node, dict):
        errors.append(f"{path}: expected dict, got {type(node).__name__}")
        return

    if "all" in node:
        children = node["all"]
        if not isinstance(children, list):
            errors.append(f"{path}.all: expected list, got {type(children).__name__}")
            return
        for i, child in enumerate(children):
            _validate_node(child, errors, path=f"{path}.all[{i}]")
    elif "any" in node:
        children = node["any"]
        if not isinstance(children, list):
            errors.append(f"{path}.any: expected list, got {type(children).__name__}")
            return
        for i, child in enumerate(children):
            _validate_node(child, errors, path=f"{path}.any[{i}]")
    else:
        # Leaf node: must have fact, op, value
        for key in ("fact", "op", "value"):
            if key not in node:
                errors.append(f"{path}: missing required key '{key}'")
        if "op" in node and node["op"] not in _VALID_OPS:
            errors.append(f"{path}: unknown operator '{node['op']}' (valid: {_VALID_OPS})")
        if "op" in node and node["op"] == "in":
            val = node.get("value")
            if val is not None and not isinstance(val, (list, tuple, set)):
                errors.append(f"{path}: 'in' operator requires a list value, got {type(val).__name__}")


def evaluate_condition(condition: dict, facts: dict[str, Any]) -> bool:
    """Evaluate an all/any condition tree against a flat fact map.

    Missing facts cause the leaf condition to evaluate to False.
    """
    if "all" in condition:
        return all(evaluate_condition(c, facts) for c in condition["all"])
    if "any" in condition:
        return any(evaluate_condition(c, facts) for c in condition["any"])

    fact_key = condition["fact"]
    op = condition["op"]
    expected = condition["value"]
    actual = facts.get(fact_key)

    # Explicit contract: missing fact → False
    if actual is None and fact_key not in facts:
        return False

    if op == "eq":
        return actual == expected
    if op == "in":
        return actual in expected

    raise ValueError(f"Unknown operator: {op}")
