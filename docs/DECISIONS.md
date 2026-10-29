# Decision Index — Menshen

Architecture decisions are recorded as individual ADR files in `docs/memory/decisions/`.
See `docs/memory/decisions/_TEMPLATE.md` for the ADR format.

| Date | File | Decision |
|------|------|----------|
| 2026-10-29 | [0001](memory/decisions/0001-seatbelt-via-sandbox-exec-and-log-stream.md) | Enforce with `sandbox-exec`; observe with a live kernel `log stream`, plus a canary to prove the stream is live |
| 2026-10-29 | [0002](memory/decisions/0002-swift-no-dependencies.md) | Swift with no third-party dependencies |
| 2026-10-29 | [0003](memory/decisions/0003-config-model-and-hardening.md) | JSON config; learned rules, then hardening rules (last match wins); flag-and-deny |
| 2026-10-29 | [0004](memory/decisions/0004-allow-apple-services-and-preferences.md) | Always allow `com.apple.*` mach services and Apple/global preference reads (learning can't see them) |
