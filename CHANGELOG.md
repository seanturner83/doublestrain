# Changelog

## 0.2.0 (2026-10-29)

Python, Rust and JVM, each measured on blind-labelled real apps (see the README's Results).

- **Settling rules:** pip, Cargo and Maven settle `not_reachable` only as the `split` +
  `claude` pair (Opus by default for these ecosystems); every other tier stays held there.
  Maven uses split's `not_reachable` from 0.90 (a per-ecosystem floor,
  `not_reachable_by_ecosystem` in `floors.toml`), and on Maven a Java deserialization
  gadget (`readObject`/`readResolve`/`readExternal`) never settles.
- **Python:** what the app's Dockerfile installs counts as production, whatever the group,
  extra or requirements file is called (`imagedeps`); local projects it installs beside the
  app are app code (`approots`); notes on who imports and calls the vulnerable package.
- **Rust:** Cargo feature resolution over the manifests (`cargofeat`), so a locked crate the
  deployed binary never compiles is known as such; Dockerfile `cargo build` lines, including
  cross-build wrappers.
- **JVM:** the deployed classpath read from the release artifact (`jvmjars`; tarballs, zips,
  fat jars, wars), every jar identified by its Maven coordinates or a Maven Central sha1
  match; `doublestrain scan --artifact`; Central-verified `-sources.jar`s and published `.pom`
  edges for the judges; a bytecode call graph from the advisory's classes back to the app's
  code (`jvmcallers`).
- **Package names:** one rule per ecosystem for "is this the same package?" (`names`).
- **Cases:** Python, Rust and JVM apps, labelled blind with a re-review; four JVM cases
  are not published yet.

## 0.1.0 (2026-10-23)

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
