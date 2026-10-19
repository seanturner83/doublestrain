# Changelog

## 0.1.0 (unreleased)

First public release.

- SSVC Act / Attend / Track grading from CISA KEV, FIRST EPSS, exposure and a
  reachability fact; malicious package versions bypass reachability and grade Act.
- Lockfile scanning to OSV advisories for npm, pip, Cargo and Go (`doublestrain scan`).
- Reachability tiers, run as a cascade with per-model acceptance floors
  (`judges/floors.toml`): govulncheck (Go call graph), Jelly (npm modules, static),
  local/LAN OpenAI-compatible models, `split` (Claude reads only dependency source),
  `shape` (Claude also sees abstracted call shapes), `claude`, and the optional `jev`.
- Guards on `not_reachable`: disagreement escalation, a second read for weak models,
  the connect guard with checked evidence for "doesn't reach", the unmeasured-ecosystem
  hold, and an installed-copy note so models reason about the right copy.
- Egress modes (`any`, `shape`, `network`, `machine`) for where app source may go.
- Integrity-verified, never-executed dependency source (npm, Go modules, crates).
- Harness (`doublestrain run`, `score`, `compare`), labelled cases, usage ledger.
