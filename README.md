ClawShield

[![PyPI version](https://img.shields.io/pypi/v/clawshield.svg)](https://pypi.org/project/clawshield/)
[![Python versions](https://img.shields.io/pypi/pyversions/clawshield.svg)](https://pypi.org/project/clawshield/)
[![CI](https://github.com/policygate/clawshield/actions/workflows/ci.yml/badge.svg)](https://github.com/policygate/clawshield/actions)

ClawShield is a security audit tool for OpenClaw deployments.

It performs static security analysis of OpenClaw configurations and host posture to detect common high-risk misconfigurations.

ClawShield is the first module released under the PolicyGate umbrella — a runtime policy enforcement framework for AI agents.

What ClawShield Checks
Network Exposure

Public bind address (0.0.0.0, ::)

Authentication disabled while publicly exposed

Container Posture

Containers running as root

Containers running in privileged mode

Secrets Handling

API keys present in .env files

API key references inside config files

File Permissions

World-writable config files

World-readable or world-writable .env files

What ClawShield Does NOT Check

Runtime exploitability

Kernel vulnerabilities

Docker daemon hardening

Firewall configuration

Intrusion detection

Secrets entropy analysis

Cloud IAM posture

ClawShield is a static audit tool, not a runtime protection system.

Installation (Development)

Clone the repository:

git clone https://github.com/policygate/clawshield.git
cd clawshield


Install locally:

pip install -e .

Usage

Run audit:

python -m clawshield path/to/openclaw.yaml


JSON mode:

python -m clawshield --json path/to/openclaw.yaml


Control exit threshold:

python -m clawshield --fail-on high path/to/openclaw.yaml


Severity ranking:

low < medium < high < critical

Exit Codes
Code	Meaning
0	No findings at or above threshold
1	Findings at or above threshold
JSON Output Contract (v0.1)
{
  "meta": {
    "schema_version": "0.1",
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


The JSON schema is versioned and locked via golden tests to prevent drift.

Architecture

ClawShield consists of:

Scanners → Collect facts from runtime and configuration

Policy Engine → Evaluates YAML rules against collected facts

Structured Output → Designed for automation and CI pipelines

Scanners are modular and isolated from the engine core.

Roadmap

Continuous monitoring mode

CI integration

Agent-agnostic security profile

Advanced secrets detection

Automated remediation plans

Status

Early release. Actively evolving.

Feedback and contributions welcome.

License

Apache 2.0

Security Disclaimer

ClawShield surfaces rule-based misconfigurations according to the active policy set. It does not guarantee system security.