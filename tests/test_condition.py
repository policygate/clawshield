import pytest

from clawshield.core.condition import evaluate_condition, validate_condition

NET001_CONDITION = {
    "all": [
        {"fact": "network.bind_address", "op": "in", "value": ["0.0.0.0", "::"]},
        {"fact": "runtime.auth_enabled", "op": "eq", "value": False},
    ]
}


# --- evaluate_condition ---

def test_triggers_on_public_bind_without_auth():
    facts = {"network.bind_address": "0.0.0.0", "runtime.auth_enabled": False}
    assert evaluate_condition(NET001_CONDITION, facts) is True


def test_triggers_on_ipv6_wildcard():
    facts = {"network.bind_address": "::", "runtime.auth_enabled": False}
    assert evaluate_condition(NET001_CONDITION, facts) is True


def test_no_trigger_on_localhost():
    facts = {"network.bind_address": "127.0.0.1", "runtime.auth_enabled": False}
    assert evaluate_condition(NET001_CONDITION, facts) is False


def test_no_trigger_when_auth_enabled():
    facts = {"network.bind_address": "0.0.0.0", "runtime.auth_enabled": True}
    assert evaluate_condition(NET001_CONDITION, facts) is False


def test_no_trigger_when_both_safe():
    facts = {"network.bind_address": "127.0.0.1", "runtime.auth_enabled": True}
    assert evaluate_condition(NET001_CONDITION, facts) is False


def test_any_condition():
    condition = {
        "any": [
            {"fact": "a", "op": "eq", "value": 1},
            {"fact": "b", "op": "eq", "value": 2},
        ]
    }
    assert evaluate_condition(condition, {"a": 1, "b": 99}) is True
    assert evaluate_condition(condition, {"a": 99, "b": 2}) is True
    assert evaluate_condition(condition, {"a": 99, "b": 99}) is False


def test_missing_fact_returns_false():
    facts = {"runtime.auth_enabled": False}
    assert evaluate_condition(NET001_CONDITION, facts) is False


def test_fact_present_but_none_still_evaluates():
    """A fact explicitly set to None should still be compared, not short-circuited."""
    condition = {"fact": "x", "op": "eq", "value": None}
    assert evaluate_condition(condition, {"x": None}) is True


# --- validate_condition ---

def test_validate_valid_condition():
    errors = validate_condition(NET001_CONDITION)
    assert errors == []


def test_validate_missing_fact_key():
    condition = {"op": "eq", "value": True}
    errors = validate_condition(condition)
    assert any("missing required key 'fact'" in e for e in errors)


def test_validate_missing_op_key():
    condition = {"fact": "x", "value": True}
    errors = validate_condition(condition)
    assert any("missing required key 'op'" in e for e in errors)


def test_validate_unknown_operator():
    condition = {"fact": "x", "op": "regex", "value": ".*"}
    errors = validate_condition(condition)
    assert any("unknown operator" in e for e in errors)


def test_validate_in_with_non_list_value():
    condition = {"fact": "x", "op": "in", "value": "not-a-list"}
    errors = validate_condition(condition)
    assert any("requires a list value" in e for e in errors)


def test_validate_nested_error():
    condition = {"all": [{"any": [{"fact": "x", "op": "bad", "value": 1}]}]}
    errors = validate_condition(condition)
    assert any("unknown operator" in e for e in errors)
    assert any("all[0].any[0]" in e for e in errors)
