# ClawShield

[![PyPI version](https://img.shields.io/pypi/v/clawshield.svg)](https://pypi.org/project/clawshield/)
[![Python versions](https://img.shields.io/pypi/pyversions/clawshield.svg)](https://pypi.org/project/clawshield/)
[![CI](https://github.com/policygate/clawshield/actions/workflows/ci.yml/badge.svg)](https://github.com/policygate/clawshield/actions)
[![PyPI downloads](https://img.shields.io/pypi/dm/clawshield)](https://pypi.org/project/clawshield/)

ClawShield detects high-risk misconfigurations in OpenClaw agents before they become exposed attack surfaces.

It is the first release under the PolicyGate umbrella — a runtime policy enforcement framework for AI agents.

## Why This Exists

AI agents are often deployed:

- Publicly bound to `0.0.0.0`
- With authentication disabled
- Inside privileged or root containers
- With API keys sitting in `.env` files
- Without file permission hardening

These are not theoretical risks — they are common misconfigurations.

ClawShield surfaces them deterministically and exits non-zero in CI when thresholds are exceeded.

## What ClawShield Checks

### Network Exposure

- Public bind address (`0.0.0.0`, `::`)
- Authentication disabled while publicly exposed

### Container Posture

- Containers running as root
- Containers running in privileged mode

### Secrets Handling

- API keys present in `.env` files
- API key references inside config files

### File Permissions

- World-writable config files
- World-readable or world-writable `.env` files

## What ClawShield Does NOT Check

- Runtime exploitability
- Kernel vulnerabilities
- Docker daemon hardening
- Firewall configuration
- Intrusion detection
- Secrets entropy analysis
- Cloud IAM posture

ClawShield is a static audit tool, not a runtime protection system.

## Quick Start (Users)

```bash
pip install clawshield
```

Run audit:

```bash
clawshield path/to/openclaw.yaml
```

JSON mode:

```bash
clawshield --json path/to/openclaw.yaml
```

Fail CI on severity threshold:

```bash
clawshield --fail-on high path/to/openclaw.yaml
```

Severity ranking:

`low` < `medium` < `high` < `critical`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above threshold |
| 1 | Findings at or above threshold |

## Example JSON Output

```json
{
  "meta": {
    "schema_version": "0.1",
    "tool_version": "0.3.0",
    "policy_path": "clawshield/policies/vps_public.yaml"
  },
  "facts": [
    {
      "key": "network.bind_address",
      "value": "0.0.0.0",
      "source": "openclaw_config:openclaw.yaml"
    },
    {
      "key": "runtime.auth_enabled",
      "value": false,
      "source": "openclaw_config:openclaw.yaml"
    }
  ],
  "findings": [
    {
      "rule_id": "NET-001",
      "title": "Public bind address with authentication disabled",
      "severity": "critical",
      "confidence": "high",
      "evidence": [],
      "recommended_actions": ["ACT-ENABLE-AUTH"],
      "autofix_available": true
    }
  ]
}
```

JSON output is deterministic and schema-versioned.
Golden tests lock the schema to prevent drift.

## Architecture

ClawShield consists of:

- **Scanners** — Collect facts from runtime and configuration
- **Policy Engine** — Evaluates YAML rules against collected facts
- **Structured Output** — Designed for automation and CI pipelines

Scanners are modular and isolated from the engine core.

## Roadmap

- Continuous monitoring mode
- Additional runtime adapters
- Expanded Docker hardening checks
- Policy bundles
- Advanced secrets detection
- Signed policy packs

## Status

Early release. Actively evolving.

Feedback and contributions welcome.

## License

Apache 2.0

## Security Disclaimer

ClawShield surfaces rule-based misconfigurations according to the active policy set.
It does not guarantee system security.
