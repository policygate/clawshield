# ClawShield MVP Scope

## In Scope (v0.1)

- CLI audit command
- Detection of:
  - Public bind address
  - Missing authentication
  - Docker privileged/root containers
  - Basic secret leakage patterns
- Policy engine evaluation
- Findings output (table + JSON)
- Safe remediation planning (no blind auto-fix)
- Docker compose patch suggestion
- Reverse proxy config template generation

---

## Out of Scope (MVP)

- Runtime sandboxing
- Skill signing
- Enterprise multi-user support
- Cloud provider APIs
- Active runtime monitoring
- Intrusion detection
- Telemetry

---

## Success Criteria

- Detect at least two high-severity misconfigurations reliably
- Produce actionable remediation steps
- Avoid breaking user systems
- Remain modular for future adapter expansion
