PolicyGate

Runtime policy enforcement for AI agents.

PolicyGate is a lightweight security audit and policy evaluation framework for AI agent deployments. It verifies that agent environments comply with defined safety, authentication, and runtime hardening rules before and during execution.

The first implementation, ClawShield, provides security auditing for OpenClaw deployments.

Why PolicyGate?

Agentic AI systems introduce new operational risks:

Public network exposure

Disabled authentication

Root / privileged container execution

API key leakage via environment files

Configuration drift across hosts

PolicyGate provides:

Deterministic policy evaluation

Structured JSON output for automation

CI/CD integration via severity thresholds

Extensible scanner architecture

Minimal runtime dependencies

It is intentionally narrow and auditable — not a black-box security scanner.

ClawShield (v0.1)

ClawShield audits OpenClaw deployments for common high-risk misconfigurations.

Current Checks
Rule ID	Description	Severity
NET-001	Public bind address with authentication disabled	Critical
DOC-001	Host has containers running as root or privileged	High
SEC-001	API keys present in .env or config files	Medium
Installation

Clone the repository:

git clone https://github.com/<your-org>/policygate.git
cd policygate


Install locally:

pip install -e .


Run:

python -m clawshield path/to/openclaw.yaml

Usage
Human-readable output
python -m clawshield openclaw.yaml

JSON output (for automation)
python -m clawshield --json openclaw.yaml

Fail CI on severity threshold
python -m clawshield --fail-on high openclaw.yaml


Severity ranking:

low < medium < high < critical

JSON Schema (v0.1)

All JSON output includes:

{
  "meta": {
    "schema_version": "0.1",
    "policy_path": "...",
    "warnings": []
  },
  "facts": [...],
  "findings": [...]
}


Golden tests lock this schema to prevent drift.

Design Principles

No remote calls

No telemetry

No mutation of configs

Deterministic rule evaluation

Fail-safe defaults

Minimal DSL (all / any / eq / in)

Explicit evidence attribution

Architecture

PolicyGate consists of:

Scanners → Collect facts from runtime and configuration

Policy Engine → Evaluates YAML rules against collected facts

Structured Output → Designed for automation and CI pipelines

Scanners are modular and isolated from the engine core.

Roadmap

Additional agent runtime adapters

Docker hardening checks (capabilities, mounts)

Policy bundles

Signed policy packs

Enterprise reporting layer

Status

Early release. Actively evolving.

Feedback and contributions welcome.

License

Apache 2.0

Security Disclaimer

PolicyGate is a policy verification tool. It does not guarantee system security. It surfaces rule-based misconfigurations based on the provided policy set.
