# ClawShield — Milestones

## v0.3.0 Release & PolicyGate Launch (2026-02-11)

### PyPI Publication

- Fixed `v0.3.0` git tag — was pointing to `55f3c09` (`version = "0.1.0"`), retagged to `c21e7a0` (`version = "0.3.0"`)
- Force-updated tag on GitHub remote
- Built sdist + wheel via `python -m build`
- `twine check` passed for both distributions
- **Published to PyPI**: `pip install clawshield` now installs v0.3.0
- Verified public install in isolated venv: installs from PyPI, CLI entrypoint works, dependencies resolve, no local path leakage

### README Overhaul

- Added badges: PyPI version, Python versions, CI status, PyPI downloads
- Replaced placeholder JSON schema with concrete example output (NET-001 finding)
- Full rewrite: added "Why This Exists" motivation section, proper Markdown formatting (`#` headers, code fences, pipe tables, bullet lists), updated roadmap
- Old README preserved locally as `README.old.md`

### PolicyGate Landing Page

- Created `policygate/policygate.github.io` repo on GitHub
- Built static HTML/CSS landing page (dark theme, responsive, no dependencies)
- **9 sections**: nav bar, hero, problem statement, PolicyGate overview, ClawShield product card, how-it-works pipeline, roadmap, waitlist (Formspree), footer
- `CNAME` configured for `policygate.dev`
- Deployed to GitHub Pages

### Formspree & DNS Configuration

- Created Formspree account and connected waitlist form (endpoint `xbdaoobj`)
- Configured DNS at Namecheap: 4 A records → GitHub Pages IPs, CNAME `www` → `policygate.github.io`
- GitHub Pages DNS check successful for `policygate.dev`
- Removed stale Namecheap parking records (URL Redirect, duplicate CNAME) that were blocking SSL provisioning
- **Pending**: Enforce HTTPS checkbox — waiting for GitHub to provision Let's Encrypt certificate

### OpenClaw Installation (2026-02-15)

- Installed OpenClaw v2026.2.14 on WSL2 (Ubuntu 24.04)
- Upgraded Node.js from v20 to v22.22.0 (OpenClaw requirement)
- Manual onboard with secure defaults:
  - Gateway: `ws://127.0.0.1:18789` (loopback, token auth)
  - Model provider: Anthropic API key (Claude Opus 4.6)
  - Tailscale: off
  - Channels: none configured (not needed for dev)
  - Sandbox: not configured (default = off — future ClawShield rule candidate)
- Gateway running as systemd user service with lingering enabled
- Config file at `~/.openclaw/openclaw.json` — this is ClawShield's primary scan target
- OpenClaw's built-in `security audit` reports 0 critical, 2 warn, 1 info on default config
- **Key observation**: No `sandbox`, `dmPolicy`, or `tools` policy configured — all relying on defaults. These are the gaps ClawShield should detect.

### v0.3.1 Patch Release (2026-02-15)

- **Critical bug fix**: Config scanner could not parse OpenClaw's native JSON format (`openclaw.json`)
  - Scanner only understood YAML paths (`server.bind_address`, `auth.enabled`)
  - OpenClaw uses JSON with different paths (`gateway.bind`, `gateway.auth.mode`) and semantic values (`"loopback"`, `"lan"`, `"token"`, `"none"`)
  - Result: ClawShield silently returned zero findings on a real OpenClaw install — a false negative on the primary scan target
- **Config scanner rewrite** (`clawshield/scanners/openclaw/config.py`):
  - Added JSON loading with format auto-detection (JSON tried first for `.json` files, then YAML fallback)
  - OpenClaw bind mode mapping: `loopback` → `127.0.0.1`, `lan`/`public` → `0.0.0.0`
  - OpenClaw auth mode mapping: `token`/`password` → enabled, `none`/missing → disabled
  - Separated into `_extract_json_facts()` and `_extract_yaml_facts()`
  - Added `~/.openclaw/openclaw.json` as first search path in adapter
- **Validated against live OpenClaw**:
  - Secure config (loopback + token auth): clean scan, no findings
  - Auth set to `"none"`: `runtime.auth_enabled=false` detected correctly
  - Bind set to `"lan"` + auth `"none"`: NET-001 fires at CRITICAL with both evidence facts
- **Golden tests use dynamic version**: Replaced 4 hardcoded `"0.3.0"` assertions with `__version__` import
- **Added `test_version.py`**: Ensures `__init__.py` and `pyproject.toml` versions stay in sync
- **Published to PyPI**: `pip install clawshield` now installs v0.3.1
- Tests: 85 → 94

### PolicyGate Website Live

- HTTPS certificate provisioned by GitHub/Let's Encrypt
- Enforce HTTPS enabled — `policygate.dev` fully operational
- Waitlist form confirmed working (Formspree dashboard shows submissions)

### v0.3.2 Packaging Fix (2026-02-15)

- **Bug**: `pip install clawshield` on WSL2 hit `FileNotFoundError` for `vps_public.yaml` — policy YAML files were not included in the wheel
- **Fix**: Added `[tool.setuptools.package-data]` section to `pyproject.toml`: `clawshield = ["policies/*.yaml"]`
- **Runtime self-check**: Added missing-policy detection in `__main__.py` — prints helpful reinstall suggestion if policy file not found
- **`.gitattributes`**: Added to force LF line endings (`* text=auto eol=lf`)
- **Published to PyPI**: v0.3.2 verified working on WSL2 with live OpenClaw

### v0.4.0 — Expanded Detection Rules (2026-02-16)

- **7 new detection rules** in `vps_public.yaml` (total now 11):
  - NET-002: Public interface with password-based auth (high)
  - AUTH-001: Weak or placeholder authentication token (medium)
  - SANDBOX-001: No sandbox isolation for shell/browser tools — elevated blast radius (high)
  - TOOL-001: Shell execution enabled (medium)
  - TOOL-002: Browser automation enabled (medium)
  - SEC-001: API keys in plaintext (high) — already existed
  - FILE-001: File permissions (high) — already existed
  - LOG-001: Sensitive data redaction disabled (medium)
  - LOG-002: File logs contain unredacted sensitive data (low)
- **Expanded fact extraction** in `_extract_json_facts()`:
  - `runtime.auth_mode`, `runtime.auth_token_length`, `runtime.auth_token_weak`
  - `sandbox.enabled`, `tools.shell_enabled`, `browser.enabled`
  - `logging.redaction_enabled`, `logging.file_logs_redacted`
  - All defaulted values tagged with `(defaulted)` in source string
- **Token weakness detection**: Length < 32 chars OR matches placeholder patterns (`changeme`, `default`, `password`, etc.)
- **Shell enabled logic**: Derived from `tools.profile` + `tools.deny` list; shell profiles = `full`, `coding`
- **Browser enabled logic**: Checks `browser.enabled` key and `tools.deny` list
- **Documented defaults applied**: sandbox=off, shell=enabled (full profile), browser=enabled, redaction=tools (console only)
- **20 new engine tests** for all 7 new rules
- **12 new scanner tests** for defaults tagging, explicit overrides, token weakness, redaction
- **Published to PyPI**: v0.4.0 verified working on WSL2 against live OpenClaw
- **Secure PyPI workflow**: Set up `.pypirc` for credential storage (no more pasting tokens in chat)
- Tests: 94 → 126+

### VPS Hardening — In Progress (2026-02-17)

#### Setup
- Provisioned Hostinger VPS with OpenClaw pre-installed template
- **OS**: Ubuntu with Docker
- **OpenClaw**: Runs inside Docker container `openclaw-lbub-openclaw-1` (image `ghcr.io/hostinger/hvps-openclaw:latest`)
- **Config location**: `/data/.openclaw/openclaw.json` inside the container (NOT at `~/.openclaw/`)
- SSH access established as root

#### Security Assessment (from reading `openclaw.json`)

**Critical/High issues found:**
- Port 64120 publicly exposed on `0.0.0.0` via Docker port mapping — anyone on the internet can reach it
- `allowInsecureAuth: true` — credentials sent in plaintext (no HTTPS enforcement)
- No sandbox isolation — no sandbox config, defaults to OFF
- Browser running with `noSandbox: true` — Chrome has no OS-level sandboxing
- Shell execution enabled (`commands.bash: true`)
- Nexos API key stored in plaintext in config
- Same auth token reused across gateway, remote, and hooks (3 places)
- 6 messaging plugins enabled (WhatsApp, Discord, Telegram, Slack, Nostr, Google Chat) — large attack surface

**Medium issues:**
- Auth token is exactly 32 characters (borderline minimum)
- Browser automation enabled in headless mode

**Credentials exposed in chat (MUST ROTATE):**
- Gateway/remote/hooks auth token
- Nexos API key
- Phone number in WhatsApp allowFrom

#### Completed (2026-02-17)

1. **Public exposure eliminated (critical fix)** *(with ChatGPT)*
   - Edited `/docker/openclaw-lbub/docker-compose.yml`: changed `"${PORT}:${PORT}"` to `"127.0.0.1:${PORT}:${PORT}"`
   - Restarted container — `docker ps` confirms `127.0.0.1:64120->64120/tcp`
   - Verified from PowerShell: `TcpTestSucceeded: False` — OpenClaw no longer internet-accessible
2. **UFW firewall active** — Port 22 allowed, port 64120 denied, firewall persistent
3. **Token segmentation** — Replaced single reused 32-byte token with three independently generated 64-hex tokens for `gateway.auth`, `gateway.remote`, and `hooks`. Verified via `jq length` checks. Container restarted.
4. **ClawShield installed on VPS** — venv at `/opt/clawshield-venv`, scan validated against real deployment
5. **SSH hardening complete** *(with ChatGPT)*
   - Created non-root user `jon` with sudo access
   - Generated ED25519 SSH key, installed public key
   - Disabled root login, password auth, keyboard-interactive auth
   - Durable override at `/etc/ssh/sshd_config.d/99-hardening.conf` (survives cloud-init)
   - Verified: `ssh jon@IP` works (key only), password auth rejected, root login rejected
6. **Post-hardening ClawShield scan results:**
   - `[HIGH] DOC-001` — Container running as root
   - `[HIGH] SANDBOX-001` — No sandbox + shell + browser enabled
   - `[MEDIUM] TOOL-001` — Shell execution enabled
   - `[MEDIUM] TOOL-002` — Browser automation enabled
   - `[LOW] LOG-002` — File logs unredacted
   - NET-001, NET-002, AUTH-001 did NOT fire — network posture is hardened

**Nexos clarification**: Nexos is the AI gateway/model provider abstraction configured in the Hostinger OpenClaw template (routes to GPT, Claude, Gemini, etc.). Key may be Hostinger-provisioned.

#### Product Insight: ClawShield Detection Gap

**NET-001 would not have fired even BEFORE the Docker bind fix.** The `openclaw.json` has no `gateway.bind` field — only `gateway.mode: "local"`. ClawShield's scanner looks for `gateway.bind` and gets empty string, which doesn't match `["0.0.0.0", "::"]`. The actual public exposure came from Docker's port mapping in `docker-compose.yml`, which ClawShield doesn't inspect. The network hardening was confirmed by `docker ps` and PowerShell, not by ClawShield. This is a real product gap to track — see roadmap below.

#### ~~Phase 1: Capability Reduction~~ — COMPLETE (2026-02-17)

- [x] Disabled browser: added `tools.deny: ["browser"]`
- [x] Enabled sandbox: set `agents.defaults.sandbox.mode: "container"`
- [x] Set `allowInsecureAuth: false`
- [x] Shell already disabled via `commands.bash: false` (done earlier with ChatGPT)
- [x] Restarted container and re-scanned — SANDBOX-001, TOOL-001, TOOL-002 all resolved
- **Scanner fix**: `commands.bash` precedence added to fact extraction (was causing false positive TOOL-001)
  - New precedence: `commands.bash` → `tools.deny` → `tools.profile` → documented default
  - 5 new tests added, 130 total passing
  - Jon's user-owned venv at `~/clawshield-venv` on VPS (replaces root-owned `/opt/clawshield-venv`)

**Post-Phase-1 scan results (2 remaining):**
- `[HIGH] DOC-001` — Container running as root
- `[LOW] LOG-002` — File logs unredacted

#### Current State (post-Phase 4 — hardening complete)

OpenClaw on VPS is:
- **Not publicly accessible** (Docker bound to 127.0.0.1, UFW blocking 64120)
- Docker capabilities minimal (`cap_drop: ALL`, only CHOWN/SETUID/SETGID/DAC_READ_SEARCH)
- Container starts as root but **app runs as `node` (uid=1000)** via `runuser`
- Shell disabled, browser disabled, sandbox enabled
- `allowInsecureAuth: false`
- Tokens segmented (gateway, remote, hooks each independent 64-hex)
- Messaging plugins reduced to 2 (Slack + Google Chat)
- SSH: key-only, root login disabled, non-root user `jon`, fail2ban active
- Running with Nexos gateway (key rotation pending — contact Hostinger)
- **Fully hardened baseline**

**Remaining scan results (2, both mitigated):**
- `[HIGH] DOC-001` — Container configured as root (mitigated: app runs as `node`, caps dropped, scanner gap)
- `[LOW] LOG-002` — File logs unredacted (accepted risk: no log files exist, scanner hardcodes behavior)

**One pending action:**
- Contact Hostinger support to rotate Nexos API key (exposed in chat, Hostinger-managed)

#### ~~Phase 2: Container Hardening~~ — COMPLETE (2026-02-18)

- [x] `cap_drop: ALL` — all Linux capabilities dropped
- [x] `cap_add: [CHOWN, SETUID, SETGID, DAC_READ_SEARCH]` — minimal set for entrypoint
- [x] Investigated non-root: image uses root→`runuser -u node` pattern (PID 1 root, app runs as `node` uid=1000)
- [ ] `no-new-privileges` — **NOT compatible** with this image (blocks `runuser` and `chown` on `drwx------` dirs)
- DOC-001 still fires: container configured as root, but app runs as `node` — **scanner product gap** (checks docker config user, not actual process user)
- **Product insight**: ClawShield should optionally check running process user via `docker exec ps`, not just `docker inspect` config

#### ~~Phase 3: Log Hygiene~~ — COMPLETE (2026-02-18, accepted risk)

- **LOG-002 accepted risk**: No log sinks configured, no log files exist on disk, OpenClaw is localhost-only behind firewall. Finding is based on documented default behavior (console-only redaction), not actual exposure. Risk is theoretical with zero realized impact.
- Scanner hardcodes `logging.file_logs_redacted = False` per OpenClaw docs regardless of config — setting `redactSensitive: "all"` would not clear the finding
- **Product backlog created** (see roadmap):
  - Scanner should detect absence of log files and suppress/downgrade LOG-002 to info
  - Scanner should trust `redactSensitive: "all"` when explicitly set instead of hardcoding `False`

#### ~~Phase 4: Secret & Auth Hygiene~~ — COMPLETE (2026-02-18)

- [x] ~~Eliminate token reuse~~ — Done: three independent 64-hex tokens
- [x] ~~Rotate gateway auth token~~ — Done via token segmentation
- [x] ~~Set `allowInsecureAuth: false`~~ — Done in Phase 1
- [x] Messaging plugins reduced from 6 to 2 — disabled WhatsApp, Discord, Telegram, Nostr; kept Slack + Google Chat
- [x] WhatsApp channel config removed (OpenClaw regenerates `allowFrom` from `.env` on startup — plugin is disabled so non-functional)
- [ ] **Pending**: Rotate Nexos API key — Hostinger-managed, no self-service rotation in dashboard. Contact Hostinger support to request rotation (key was exposed in Claude chat session)

#### ~~Phase 5: SSH & Host Hardening~~ — COMPLETE

- [x] Created non-root user `jon` with sudo
- [x] ED25519 key-based SSH auth
- [x] Disabled password auth and root login
- [x] Durable config at `/etc/ssh/sshd_config.d/99-hardening.conf`

#### ~~Phase 5b: Defense-in-Depth~~ — COMPLETE (2026-02-18)

- [x] fail2ban installed, enabled, and running
- [x] SSH jail active (default: bans after 5 failed attempts for 10 minutes)
- [x] Persistent across reboots (`systemctl enable`)

### Next Steps (after VPS hardening)

- **License deprecation**: Update `pyproject.toml` license format from `{text = "Apache-2.0"}` to `"Apache-2.0"` (setuptools deprecation warning, deadline Feb 2027)
- **ClawShield roadmap**:
  - New rules: DM policy open, group policy open
  - **Docker-aware scanning**: Detect port exposure from `docker-compose.yml` / Docker port mapping, not just OpenClaw config (gap exposed by VPS hardening)
  - **Docker process-level user detection**: Check actual running process user via `docker exec ps`, not just `docker inspect` config user (gap exposed by Phase 2 — entrypoint pattern starts root, drops to `node`)
  - `allowInsecureAuth` detection rule
  - Token reuse detection (same token in multiple config sections)
  - ~~`commands.bash` detection~~ — **FIXED in v0.4.0+** (scanner now checks `commands.bash` with proper precedence)
  - **LOG-002 improvements** (from Phase 3 findings):
    - Detect absence of log files/sinks → suppress or downgrade LOG-002 to info/not-applicable
    - Trust explicit `redactSensitive: "all"` config → mark `logging.file_logs_redacted = True` instead of hardcoding `False`
  - Align with and eventually supersede `openclaw security audit` coverage

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
