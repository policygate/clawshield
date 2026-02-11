# ClawShield – MVP Implementation Plan

---

## 1. Architectural Over-Engineering Identified

The planning documents are well-structured but contain several elements that
are premature for an MVP. These should be deferred, not deleted.

| Element | Issue | MVP Recommendation |
|---|---|---|
| **Evidence Store (SQLite/JSONL)** | Drift detection and persistence are post-MVP concerns. No user needs a database to run a one-shot audit. | Replace with in-memory dict of facts. Add persistence later. |
| **Action Planner (separate component)** | For two rules, a dedicated planner with guardrail logic is overhead. | Inline action mapping into the policy engine output. Extract later when rule count exceeds ~10. |
| **`doctor` CLI command** | Self-diagnosis tooling is a polish feature. | Defer entirely. Ship `audit` only. |
| **`harden` CLI command** | Automated remediation execution is risky for v0.1. | Ship `audit --fix-plan` that *prints* a remediation plan. No execution. |
| **`policy validate` CLI command** | Schema validation tooling is developer-facing. | Defer. Validate policies at load time with clear errors instead. |
| **SecretsScanner** | Secret scanning is a large problem space (regex patterns, entropy analysis, allowlists). | Defer to v0.2. Focus on config-level misconfigurations. |
| **RuntimeAdapter.apply_safe_config()** | Implies the adapter can write config. MVP should be read-only. | Remove from MVP interface. Adapter is read-only. |
| **RuntimeAdapter.enumerate_extensions()** | Skill/plugin enumeration is a v0.2 feature (supply-chain awareness). | Remove from MVP interface. |
| **Reverse proxy template generation** | Useful but tangential to the core audit loop. | Defer. Mention it in findings as a manual recommendation. |
| **`autofix_max_severity` guardrail in defaults** | Implies automated execution with severity-based gating. MVP doesn't auto-execute. | Remove from MVP schema. |

**Summary:** The architecture doc describes a v1.0 system. For MVP, we need:
one CLI command (`audit`), two scanners, two rules, findings output, and a
printed remediation plan. Nothing writes to disk except the report.

---

## 2. Minimal End-to-End Vertical Slice

The thinnest possible path that proves the architecture works:

```
[OpenClawConfigScanner] → collects facts
        ↓
  { "network.bind_address": "0.0.0.0",
    "runtime.auth_enabled": false }
        ↓
[PolicyEngine] → evaluates NET-001 against facts
        ↓
  Finding {
    rule_id: "NET-001",
    severity: "critical",
    title: "Runtime bound to public interface without authentication",
    evidence: { bind_address: "0.0.0.0", auth_enabled: false },
    actions: ["Bind to 127.0.0.1", "Enable authentication", "Add reverse proxy"]
  }
        ↓
[CLI] → prints findings table + remediation plan
```

**What this proves:**
- Scanner → fact collection works
- Policy YAML → rule evaluation works
- Finding generation works
- Output formatting works
- OpenClaw-specific logic is isolated in the scanner

**What this does NOT do:**
- No Docker inspection
- No file modification
- No persistence
- No automated fixes

This slice can be built and tested in 2-3 days.

---

## 3. Interface Definitions

### 3.1 RuntimeAdapter (Protocol)

```python
class RuntimeAdapter(Protocol):
    """Read-only adapter for a specific agent runtime."""

    def detect(self) -> bool:
        """Return True if this runtime is present on the system."""
        ...

    def get_version(self) -> str | None:
        """Return the runtime version string, or None if unknown."""
        ...

    def get_config_paths(self) -> list[Path]:
        """Return paths to configuration files for this runtime."""
        ...
```

MVP keeps the adapter read-only. `apply_safe_config()` and
`enumerate_extensions()` are deferred.

### 3.2 Scanner (Protocol)

```python
class Scanner(Protocol):
    """Collects facts from the environment. Does not assign severity."""

    name: str

    def scan(self, context: ScanContext) -> list[Fact]:
        """Run the scan and return a list of facts."""
        ...
```

Supporting types:

```python
@dataclass
class Fact:
    key: str          # e.g. "network.bind_address"
    value: Any        # e.g. "0.0.0.0"
    source: str       # e.g. "openclaw_config:/etc/openclaw/config.yaml"
    collected_at: str  # ISO timestamp

@dataclass
class ScanContext:
    adapter: RuntimeAdapter
    config_paths: list[Path]
```

### 3.3 PolicyEngine

```python
class PolicyEngine:
    """Evaluates rules from YAML policies against collected facts."""

    def __init__(self, policy_paths: list[Path]) -> None:
        """Load and validate policy YAML files."""
        ...

    def evaluate(self, facts: list[Fact]) -> list[Finding]:
        """Evaluate all loaded rules against facts. Return findings."""
        ...
```

Supporting types:

```python
@dataclass
class Finding:
    rule_id: str              # "NET-001"
    title: str
    severity: str             # "critical" | "high" | "medium" | "low"
    confidence: str           # "high" | "medium" | "low"
    evidence: list[Fact]      # facts that triggered this finding
    recommended_actions: list[str]  # human-readable action descriptions
    autofix_available: bool

@dataclass
class Rule:
    id: str
    title: str
    severity: str
    confidence: str
    condition: dict           # the all/any condition tree from YAML
    actions: dict             # recommended + autofix action IDs
```

### 3.4 Remediator (Protocol)

```python
class Remediator(Protocol):
    """Produces a remediation plan for a finding. Does NOT execute it in MVP."""

    def can_handle(self, finding: Finding) -> bool:
        """Return True if this remediator knows how to address this finding."""
        ...

    def plan(self, finding: Finding) -> RemediationPlan:
        """Generate a non-destructive remediation plan."""
        ...
```

Supporting type:

```python
@dataclass
class RemediationPlan:
    finding_id: str
    steps: list[RemediationStep]

@dataclass
class RemediationStep:
    description: str       # human-readable
    type: str              # "manual" | "autofix"
    file_path: Path | None # file that would be modified
    preview: str | None    # what the change would look like (diff-style)
```

---

## 4. Module / Package Layout

```
clawshield/
├── __init__.py
├── __main__.py              # entry point: python -m clawshield
│
├── cli/
│   ├── __init__.py
│   └── audit.py             # `clawshield audit` command
│
├── core/
│   ├── __init__.py
│   ├── engine.py            # PolicyEngine
│   ├── models.py            # Fact, Finding, Rule, RemediationPlan, etc.
│   └── condition.py         # all/any condition evaluator
│
├── scanners/
│   ├── __init__.py
│   ├── base.py              # Scanner protocol
│   ├── network.py           # NetworkScanner (generic)
│   ├── docker.py            # DockerScanner (generic)  [v0.1 stretch]
│   └── openclaw/
│       ├── __init__.py
│       └── config.py        # OpenClawConfigScanner
│
├── remediators/
│   ├── __init__.py
│   ├── base.py              # Remediator protocol
│   └── openclaw/
│       ├── __init__.py
│       └── config_patcher.py  # bind-to-localhost plan
│
├── runtimes/
│   ├── __init__.py
│   ├── base.py              # RuntimeAdapter protocol
│   └── openclaw/
│       ├── __init__.py
│       └── adapter.py       # OpenClawAdapter
│
├── policies/
│   └── vps_public.yaml      # shipped default policy (NET-001, DOC-001)
│
└── output/
    ├── __init__.py
    ├── table.py              # rich/tabulate table formatter
    └── json.py               # JSON findings output
```

**Key boundaries enforced:**
- `core/` imports nothing from `scanners/`, `runtimes/`, or `remediators/`
- `scanners/openclaw/` may import from `runtimes/openclaw/`
- `cli/` orchestrates everything, wiring scanners to engine to output
- `policies/` is data only (YAML), not code

---

## 5. Language Recommendation

**Recommendation: Python**

| Criterion | Python | Go |
|---|---|---|
| CLI UX | `click` or `typer` — excellent, fast to build | `cobra` — good but more boilerplate |
| Docker inspection | `docker` SDK or subprocess `docker inspect` — trivial | `docker/client` — works but more verbose |
| YAML policy evaluation | `PyYAML` + native dict operations — natural fit | `gopkg.in/yaml.v3` — workable but more ceremony |
| Distribution | `pipx install`, single wheel, or `PyInstaller` | Single static binary — **Go wins here** |
| Development speed | Faster iteration, less boilerplate | Slower for prototyping |
| Table/rich output | `rich` library — best-in-class terminal output | `tablewriter` — functional but plain |

**Rationale:**

The MVP priority is proving the architecture, not shipping a binary. Python
lets us iterate on the policy engine DSL, test scanner logic, and refine the
CLI UX with minimal friction. The YAML-to-dict-to-evaluation pipeline is
particularly natural in Python.

Distribution is Go's only clear advantage, and it doesn't matter until we
have a product worth distributing. If distribution becomes critical, the
modular architecture allows a future port of the CLI shell to Go while
keeping the policy engine logic portable.

**Python version:** 3.11+ (for `tomllib`, modern typing, `StrEnum`)

**Key dependencies (MVP only):**
- `click` — CLI framework
- `pyyaml` — policy loading
- `rich` — table output and terminal formatting
- `dataclasses` — stdlib, for models

No other external dependencies for MVP.

---

## 6. Technical Risks and Brittleness

### 6.1 Policy Condition DSL Complexity

The `all`/`any` condition tree with operators (`eq`, `in`) is a mini
expression language. Risk: it grows into an unmaintainable DSL.

**Mitigation:** For MVP, support only `eq` and `in` operators. Hardcode the
evaluator. Do not build a generic expression parser. Add operators only when
a real rule needs them.

### 6.2 OpenClaw Config File Discovery

We don't know the exact config file format, paths, or structure of OpenClaw.
The scanner depends on reading real config files.

**Mitigation:** Build the `OpenClawAdapter.get_config_paths()` to search
known locations (`/etc/openclaw/`, `~/.openclaw/`, `./openclaw.yaml`,
environment variable `OPENCLAW_CONFIG`). Fail gracefully with a clear message
if no config is found. Support passing an explicit path via CLI flag.

### 6.3 Docker Socket Access

Docker inspection requires access to `/var/run/docker.sock`, which typically
requires root or `docker` group membership. Users running ClawShield without
these permissions will get confusing errors.

**Mitigation:** Check Docker socket accessibility at scan start. If
unavailable, skip Docker scanners with a clear warning rather than crashing.
The `audit` command should produce partial results, not fail entirely.

### 6.4 Fact Key Namespace Collisions

Facts use dot-notation keys (`network.bind_address`, `docker.user`). If
multiple scanners produce facts with the same key, results become ambiguous.

**Mitigation:** Prefix facts with scanner name scope. Document the key
namespace convention. In MVP, this is low-risk with only 2-3 scanners.

### 6.5 YAML Policy Schema Drift

The policy schema (`03_policy_schema.yaml`) has no formal validation. As
rules are added, schema drift will cause silent evaluation failures.

**Mitigation:** Add basic schema validation at policy load time using
dataclass parsing (not a full JSON Schema validator). Fail loudly on
unrecognized fields.

### 6.6 Config File Modification Safety

The remediation layer eventually needs to modify config files. This is the
highest-risk operation in the entire system.

**Mitigation for MVP:** Do not modify files. Print the remediation plan only.
When file modification is added later, enforce: backup before write, dry-run
by default, diff preview before confirmation.

---

## 7. Four-Week Build Plan

### Week 1 — Vertical Slice (NET-001 end-to-end)

- [ ] Project scaffolding: `pyproject.toml`, package structure, dev tooling
- [ ] `core/models.py`: `Fact`, `Finding`, `Rule`, `RemediationPlan` dataclasses
- [ ] `core/condition.py`: evaluate `all`/`any` with `eq` and `in` operators
- [ ] `core/engine.py`: `PolicyEngine` loads YAML, evaluates rules, returns findings
- [ ] `runtimes/openclaw/adapter.py`: `OpenClawAdapter` with `detect()`, `get_config_paths()`
- [ ] `scanners/openclaw/config.py`: `OpenClawConfigScanner` reads bind address + auth flag
- [ ] `policies/vps_public.yaml`: ship NET-001 rule
- [ ] `cli/audit.py`: `clawshield audit` prints findings to stdout
- [ ] Tests: unit tests for condition evaluator + policy engine with mock facts

**Deliverable:** `clawshield audit` detects NET-001 against a sample OpenClaw config.

### Week 2 — Second Rule + Docker Scanner

- [ ] `scanners/docker.py`: `DockerScanner` reads container user, privileged flag, capabilities
- [ ] Add DOC-001 rule to `vps_public.yaml`
- [ ] `output/table.py`: rich-formatted findings table
- [ ] `output/json.py`: JSON findings output (`clawshield audit --format json`)
- [ ] Handle Docker socket unavailable gracefully
- [ ] Tests: Docker scanner with mocked `docker inspect` output

**Deliverable:** `clawshield audit` detects both NET-001 and DOC-001, with table and JSON output.

### Week 3 — Remediation Plans + CLI Polish

- [ ] `remediators/openclaw/config_patcher.py`: plan for bind-to-localhost
- [ ] `remediators/base.py`: compose patcher plan for Docker hardening
- [ ] `cli/audit.py`: add `--fix-plan` flag to print remediation steps
- [ ] Add `--config` flag to specify OpenClaw config path explicitly
- [ ] Add `--policy` flag to specify custom policy file
- [ ] Error handling: missing config, missing Docker, invalid policy YAML
- [ ] Tests: remediation plan generation, CLI integration tests

**Deliverable:** `clawshield audit --fix-plan` shows actionable remediation steps.

### Week 4 — Testing, Packaging, Documentation

- [ ] End-to-end integration test with a sample OpenClaw deployment (Docker Compose)
- [ ] Edge cases: empty config, partial config, no Docker, multiple configs
- [ ] `pyproject.toml` packaging: `pip install clawshield`
- [ ] Minimal README with usage examples
- [ ] CI: lint (`ruff`), type check (`mypy`), test (`pytest`)
- [ ] Tag v0.1.0 release

**Deliverable:** Installable, tested, documented v0.1.0 MVP.

---

## 8. First Feature, First Test, Simplest Data Model

### First Feature to Implement

**The condition evaluator** (`core/condition.py`).

Rationale: it is the innermost component with zero external dependencies. It
takes a condition tree (dict) and a fact map (dict), and returns a boolean.
Everything else depends on it, but it depends on nothing. It can be built and
tested in isolation in under an hour.

### First Test to Write

```python
def test_net001_triggers_on_public_bind_without_auth():
    """NET-001 should fire when bind_address is 0.0.0.0 and auth is disabled."""
    facts = {
        "network.bind_address": "0.0.0.0",
        "runtime.auth_enabled": False,
    }
    condition = {
        "all": [
            {"fact": "network.bind_address", "op": "in", "value": ["0.0.0.0", "::"]},
            {"fact": "runtime.auth_enabled", "op": "eq", "value": False},
        ]
    }
    assert evaluate_condition(condition, facts) is True


def test_net001_does_not_trigger_on_localhost():
    """NET-001 should not fire when bound to localhost."""
    facts = {
        "network.bind_address": "127.0.0.1",
        "runtime.auth_enabled": False,
    }
    condition = {
        "all": [
            {"fact": "network.bind_address", "op": "in", "value": ["0.0.0.0", "::"]},
            {"fact": "runtime.auth_enabled", "op": "eq", "value": False},
        ]
    }
    assert evaluate_condition(condition, facts) is False
```

### Simplest Data Model for NET-001

```python
# Facts collected by scanner — flat dict, not a database
facts: dict[str, Any] = {
    "network.bind_address": "0.0.0.0",  # from OpenClaw config
    "runtime.auth_enabled": False,       # from OpenClaw config
}

# Finding produced by policy engine
finding = Finding(
    rule_id="NET-001",
    title="Runtime bound to public interface without authentication",
    severity="critical",
    confidence="high",
    evidence=[
        Fact(key="network.bind_address", value="0.0.0.0",
             source="openclaw_config:/etc/openclaw/config.yaml"),
        Fact(key="runtime.auth_enabled", value=False,
             source="openclaw_config:/etc/openclaw/config.yaml"),
    ],
    recommended_actions=[
        "Enable authentication in OpenClaw configuration",
        "Add a reverse proxy (nginx/caddy) with TLS and auth",
    ],
    autofix_available=True,
)
```

No database. No persistence. No ORM. Facts are a flat dict. Findings are
dataclasses. This is the minimum viable data model that supports the full
audit loop for NET-001.

---

## Summary

| Decision | Choice |
|---|---|
| Language | Python 3.11+ |
| First command | `clawshield audit` |
| First scanner | `OpenClawConfigScanner` |
| First rule | NET-001 |
| First test | Condition evaluator unit test |
| Persistence | None (in-memory facts) |
| Remediation | Plan-only, no execution |
| Distribution | `pip install` / `pipx` |
| Target timeline | 4 weeks to v0.1.0 |
