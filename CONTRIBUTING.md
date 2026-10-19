# Contributing

- `uv run python -m pytest -q` must pass. Tests run offline: no network, no model calls
  (a fake Jev server and a fake `claude` binary stand in).
- A change to a prompt, a pre-pass, a guard or a floor needs a measurement: run the
  harness over the labelled cases (`docs/running.md`) and report false `not_reachable`
  and coverage before and after. False `not_reachable` is the headline metric; a change
  that raises it needs a strong reason.
- Floors live in `src/ssvc_triage/judges/floors.toml`, each with what it was measured on.
  A new model gets its role's defaults until it has been measured.
- Never build, install or execute code from a case checkout or a dependency package, in
  code or in tests. Read it only.
- New cases: add `case.json` and a `fetch.sh` that clones the app at a pinned commit (no
  vendored third-party code). Label each `expect` by reading the code, before running any
  judge on it, and record who labelled it and how in `labelled_by`.
- Keep the cache keys honest: if a change alters what a judge is asked, its fingerprint
  (or a per-query salt) must change, so stale answers aren't reused.
