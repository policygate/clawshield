# ClawShield — Milestones

## v0.3.0 (2026-02-09)

### Planning Phase

- Created project planning documents:
  - `01_product_vision.md` — Product vision and target audience
  - `02_architecture.md` — System architecture and design principles
  - `03_policy_schema.yaml` — Policy DSL specification
  - `04_mvp_scope.md` — MVP scope definition
  - `05_non_goals.md` — Explicit non-goals to prevent scope creep
  - `06_technical_constraints.md` — Technical constraints and boundaries
  - `07_mvp_implementation_plan.md` — Detailed 4-week build plan with interface definitions, module layout, and technical risks

### Vertical Slice (v0.1)

- Built the minimal end-to-end pipeline: scanner → fact → engine → finding → CLI output
- **Core models** (`clawshield/core/models.py`): `Fact` and `Finding` dataclasses
- **Condition evaluator** (`clawshield/core/condition.py`): `all`/`any` condition trees with `eq`/`in` operators, explicit missing-fact-returns-False contract
- **Policy engine** (`clawshield/core/engine.py`): YAML policy loading, rule validation at load time, condition validation
- **OpenClaw adapter** (`clawshield/runtimes/openclaw/adapter.py`): Config discovery with search paths, `searched_locations()` for failure UX
- **Config scanner** (`clawshield/scanners/openclaw/config.py`): Reads `bind_address` and `auth.enabled` from OpenClaw config
- **NET-001 rule**: Runtime bound to public interface without authentication (critical severity)
- **CLI entry point** (`clawshield/__main__.py`): Basic `python -m clawshield <config>` interface
- 13 tests passing

### Robustness Improvements (v0.1 → v0.2)

- Condition node validation at policy load time (rejects malformed condition trees)
- Extracted fact keys once per rule (avoid re-walking condition tree per evaluation)
- Policy validation on load with `PolicyLoadError` for malformed policies
- Fact key collision detection with source attribution in warnings
- `--json` output flag with structured JSON schema
- Scanner normalization: `_normalize_bind_address` (strip whitespace), `_normalize_bool` (string bool coercion for `"false"`/`"true"`)
- `EvalResult` return type from engine (findings + warnings)
- Warning pipeline refactored: engine returns warnings structurally, CLI handles all stderr output
- `meta.warnings` in JSON output (only present when warnings exist)
- Tests: 13 → 27

### Docker Scanner & v0.2 Features

- **Docker scanner** (`clawshield/scanners/docker.py`):
  - Inspects running containers via `docker ps` + `docker inspect`
  - Detects root user (empty string, `"root"`, UID 0) and privileged mode
  - Worst-case aggregation across all containers (host posture)
  - Diagnostic warnings: binary not found vs daemon down vs timeout
  - Safe Name/Id handling (`container.get("Id") or "unknown"`)
  - Source string capping at 5 container names (`_cap_names`)
- **DOC-001 rule**: Host has containers running as root or with elevated privileges (high severity)
- **`--fail-on` flag**: Minimum severity threshold for non-zero exit code (`low`/`medium`/`high`/`critical`)
- **`meta.schema_version`** in JSON output
- **`meta.policy_path`** in JSON output (with `.resolve()` for packaging safety)
- Improved detection failure UX: shows searched paths on config not found
- Clean message qualified: "No issues found for the checks performed"
- Tests: 27 → 53

### Golden JSON Schema Tests

- Locked the JSON output contract with 6 golden tests:
  - NET-001 only (no Docker)
  - Both NET-001 and DOC-001
  - Clean run (no findings)
  - Empty config (early return path)
  - `--fail-on` integration tests
- Human output tests: clean message qualifier, DOC-001 host-scope title
- Tests: 53 → 59

### Secrets-Lite Scanner (SEC-001)

- **Secrets scanner** (`clawshield/scanners/openclaw/secrets.py`):
  - Checks `.env` files for well-known API key names (OPENAI, ANTHROPIC, GOOGLE, AZURE, COHERE, MISTRAL, HuggingFace)
  - Checks config files for API key name references (case-insensitive)
  - Scoped to OpenClaw config directory only — no recursion, no crawling
  - `.env` checked once per directory (deduplication)
  - Always emits `secrets.env_file_present`, `secrets.api_key_in_env_file`, and `secrets.api_key_in_config` as consistent booleans
- **SEC-001 rule**: Potential API keys stored in plaintext in OpenClaw config directory (high severity)
- `.env` matching simplified to `startswith(key_name + "=")`
- Golden JSON tests updated intentionally for new facts
- Tests: 59 → 71

### File Permissions Scanner (FILE-001) & Release Prep

- **File permissions scanner** (`clawshield/scanners/openclaw/permissions.py`):
  - Detects world-writable config files
  - Detects world-readable and world-writable `.env` files
  - Gracefully skips on Windows (all facts emit False)
  - `.env` checked once per directory (deduplication)
  - Config world-readable intentionally excluded (legitimate service account access)
- **FILE-001 rule**: Configuration or secrets file is world-readable or world-writable (high severity)
- Tests use mocked `stat` results for cross-platform compatibility
- **Tool version**: `__version__ = "0.3.0"` emitted as `meta.tool_version` in JSON output
- **README.md**: What it checks, what it doesn't, installation, usage, exit codes, JSON schema sample, roadmap
- Golden JSON tests updated for `tool_version` and file permission facts
- Tests: 71 → 85

### Final State

- **4 detection rules**: NET-001 (critical), DOC-001 (high), SEC-001 (high), FILE-001 (high)
- **4 scanners**: OpenClawConfigScanner, DockerScanner, SecretsLiteScanner, FilePermissionsScanner
- **2 operators**: `eq`, `in` (YAGNI discipline maintained — no premature additions)
- **85 tests passing** across 7 test files
- **Structured JSON output** with stable, versioned schema
- **CLI** with `--json`, `--fail-on`, `--policy` flags

### Architecture Decisions Defended

- Rejected premature `gt`/`contains` operators multiple times (YAGNI)
- Rejected Docker scope filtering — host-wide posture is correct for security tool
- Rejected `HOST-DOC-001` rename — title change ("Host has...") was sufficient
- Rejected actions catalog — action IDs sufficient for MVP
- Rejected generic "multiple configs detected" warning — per-key collision warnings are more precise
- Kept `FilePermissionsScanner` separate from `SecretsLiteScanner` (single responsibility)
