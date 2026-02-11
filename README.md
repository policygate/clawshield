# ClawShield

Security audit tool for OpenClaw deployments.

ClawShield performs static security analysis of OpenClaw configurations and host posture to detect common high-risk misconfigurations.

## What ClawShield Checks

**Network Exposure**
- Public bind address (`0.0.0.0`, `::`)
- Authentication disabled while publicly exposed

**Container Posture**
- Containers running as root
- Containers running in privileged mode

**Secrets Handling**
- API keys present in `.env` files
- API key references inside config files

**File Permissions**
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

## Installation

```
pipx install clawshield
```

or

```
pip install clawshield
```

## Usage

```
clawshield path/to/openclaw.yaml
```

JSON mode:

```
clawshield --json path/to/openclaw.yaml
```

Control exit threshold:

```
clawshield --fail-on high path/to/openclaw.yaml
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | No findings at or above threshold |
| 1    | Findings at or above threshold |

## JSON Output Contract

```json
{
  "meta": {
    "schema_version": "0.1",
    "tool_version": "0.3.0",
    "policy_path": "...",
    "warnings": []
  },
  "facts": [
    {"key": "...", "value": "...", "source": "..."}
  ],
  "findings": [
    {
      "rule_id": "NET-001",
      "title": "...",
      "severity": "critical",
      "confidence": "high",
      "evidence": [],
      "recommended_actions": ["ACT-ENABLE-AUTH"],
      "autofix_available": true
    }
  ]
}
```

Schema is versioned and stable within minor releases.

## Roadmap

- Continuous monitoring mode
- CI integration
- Agent-agnostic security profile
- Advanced secrets detection
- Automated remediation plans
