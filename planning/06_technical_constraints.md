# Technical Constraints

## Language

(To be decided before implementation: Python or Go recommended.)

## Target Platforms

- Linux (primary)
- Docker environments
- VPS-hosted systems

Mac/Windows support may be added later.

---

## Security Requirements

- No network telemetry by default
- Backups required before modifying config files
- Idempotent remediations
- No destructive changes without explicit confirmation

---

## Persistence

- Local SQLite database (default)
- Optionally JSONL for lightweight mode

---

## Distribution

- Single CLI binary or installable package
- Minimal runtime dependencies
- Reproducible builds preferred

---

## Extensibility Requirement

Core modules must not import OpenClaw-specific code.

All OpenClaw logic must exist inside runtime adapter modules.

Future adapters must be pluggable without modifying core policy engine.
