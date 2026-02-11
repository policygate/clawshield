# ClawShield – Architecture Specification

## 1. Architectural Goals

- Modular
- Adapter-based
- Policy-driven
- Framework-agnostic core
- Safe remediation workflows

---

## 2. System Layers

### CLI Layer
- audit
- harden
- doctor
- policy validate

Responsible only for orchestration and output.

---

### Core Layer

#### Policy Engine
- Loads YAML policies
- Evaluates conditions against evidence
- Produces findings
- Maps findings to actions

#### Evidence Store
- Local SQLite or JSONL
- Stores scan results
- Enables drift detection

#### Findings Model
- ID
- Severity
- Confidence
- Evidence references
- Recommended actions
- Autofix eligibility

#### Action Planner
- Translates findings into actions
- Separates recommended vs autofix
- Applies guardrails

---

### Scanner Layer

Generic scanners:
- NetworkScanner
- DockerScanner
- ComposeScanner
- SecretsScanner

OpenClaw-specific scanners:
- OpenClawConfigScanner
- OpenClawSkillScanner

Scanners produce evidence only.
They do not assign severity.

---

### Remediation Layer

Generic:
- Firewall configuration templates
- Docker hardening
- Compose patcher
- Reverse proxy template generator

OpenClaw-specific:
- Config patcher
- Bind address modification
- Authentication enablement

All remediations must:
- Create backups
- Be idempotent
- Require confirmation (unless forced)

---

### Runtime Adapter Layer

Define RuntimeAdapter interface:

- detect()
- get_version()
- get_config_locations()
- enumerate_extensions()
- apply_safe_config(profile)

OpenClawAdapter implements this interface.

Future adapters:
- LangChainAdapter
- CrewAIAdapter
- GenericDockerAgentAdapter

---

## 3. Critical Constraint

OpenClaw-specific logic must exist ONLY in:

- runtimes/openclaw/
- scanners/openclaw/
- remediators/openclaw/

The policy engine and generic scanners must not depend on OpenClaw.
