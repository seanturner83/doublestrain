# ssvc-triage

Grades dependency advisories (from a lockfile scan, or Dependabot bumps) into SSVC's
**Act / Attend / Track**, using whether the vulnerable code is actually reachable in your
app. Models supply that reachability fact with evidence; a fixed decision tree
(`ssvc.py`) makes the call, from three facts: exploitation (CISA KEV, FIRST EPSS),
reachability and exposure. Every fact records where it came from (`reach_source`), and
model verdicts only count when they clear acceptance floors measured against labelled
apps (`judges/floors.toml`). A wrong "not reachable" hides a risk, so that direction is
held to the stricter standard throughout.

What's in the box:

- `src/ssvc_triage/ssvc.py`: the decision tree (`grade`, `grade_all`).
- `src/ssvc_triage/osv.py`, `cargo.py`, `gomod.py`: lockfiles (npm, pip, Cargo, Go) to
  OSV advisories to candidates. `sweep.py`: sweep JSONL records to candidates; the
  exposure map.
- `src/ssvc_triage/judges/`: the reachability tiers, run as a cascade
  (`cascade:a,b,...`), each answer cached on disk (`SSVC_JUDGE_CACHE`):
  - `govulncheck`: Go call-graph reachability, sandboxed (type-checks, never builds or runs).
  - `jelly`: which npm packages the app can load at all ([Jelly](https://github.com/cs-au-dk/jelly)
    static analysis, sandboxed); settles `not_reachable` only with a second read.
  - `local` / any named OpenAI-compatible endpoint (LM Studio, llama.cpp, Ollama, vLLM):
    a grep summary plus numbered source excerpts, one JSON-schema verdict, no tools.
    Endpoints never settle `reachable`; an off-network endpoint is refused unless it is
    https and `SSVC_<NAME>_ALLOW_CODE_EGRESS=1`.
  - `split`: claude reads only the dependency's verified source and writes a trigger
    spec; a local endpoint matches it against the app. App code stays on your machine.
  - `shape`: claude sees the dependency source plus abstracted call shapes from the app.
  - `claude`: `claude -p` in the checkout, read-only tools, `--restricted`.
  - `jev`: an optional hosted classifier (TypeSafe's Jev API; needs its own key).
- `src/ssvc_triage/feeds/`: CISA KEV and FIRST EPSS, cached (`docs/running.md`, "Exploit signals").
- `src/ssvc_triage/reach.py`: applies an accepted verdict to a candidate.
- `src/ssvc_triage/harness/`: `ssvc-run`, `ssvc-score`, `ssvc-compare`; `ssvc-scan`
  grades one repo; `ssvc-usage` summarises the model-call ledger.
- `cases/`: labelled apps. Each has `case.json`, plus `fetch.sh` for third-party checkouts.

## Quickstart

```sh
uv sync
# grade one app's dependency advisories (OSV + KEV/EPSS); no reachability judge:
uv run ssvc-scan path/to/app --judge null --exposure public-internet
# with judges: local/LAN models first, claude only on what they can't settle,
# app source never leaving your network except as abstracted call shapes
export SSVC_PKGSRC=1 SSVC_WORKSTATION_BASE_URL=http://<your-llm-host>:1234/v1
uv run ssvc-scan path/to/app --egress shape \
    --judge cascade:jelly,workstation,split:workstation,shape
```

`ssvc-scan` writes `runs/scan-<ts>-<name>/` with a digest (Act first), every grade with
its reason and reachability source, and a summary. Unresolved reachability grades like
`reachable`: no signal is never treated as safety. `docs/running.md` covers the backends
each tier needs and the run harness.

## Results

Ten deliberately vulnerable or real npm apps (1,045 advisory rows, 941 labelled),
`cascade:workstation,split:workstation,shape` (Qwen 3.8 27B on a local GPU box for the
workstation and the matcher, Claude for specs and shapes):

| Run | False not_reachable | Coverage | Note |
|---|---|---|---|
| r4 | 7 | 0.657 | floors only (348 rows lost to a usage limit) |
| r6 | 0 | 0.650 | + disagreement escalation and corroboration |
| r9 | 0 | 0.747 | + registry integrity fallback, parent triggers |
| r10 | 0 | 0.748 | + `jelly` first: 170 rows settle without a Claude tier |

Five Go apps (145 labels): govulncheck alone 0 false not_reachable at 0.959 coverage;
`split` 128 right, 0 wrong. Every change and its measurement is in `docs/design.md`.

## Labels and data

- **The labels are AI-made.** Every `expect` in `cases/` was written by a Claude model
  reading the app and the dependency source (`labelled_by` says which, and when), most of
  them blind to the judges' verdicts. Some were reviewed and corrected; none is a human
  ground truth. Treat the measured error rates as agreement with those labels.
- **Third-party apps** are not vendored: `cases/<id>/fetch.sh` clones each at the pinned
  commit it was labelled against (`for f in cases/*/fetch.sh; do sh "$f"; done`).
  Nothing in them is built or run.
- **Advisory text** in the case files and in reports comes from [OSV](https://osv.dev)
  (including the GitHub Advisory Database), licensed
  [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/); KEV is CISA's catalogue,
  EPSS is FIRST's. Fixture enrichment values in the shipped cases are not live data.
- **Network use:** OSV gets package names and versions, KEV/EPSS get CVE ids, the npm
  registry / Go proxy / crates.io get names and versions. What each judge tier sends is in
  `docs/data-handling.md`.

## Security

Dependency packages are treated as hostile bytes: integrity-verified before parsing,
never installed or executed, extracted with traversal, link and size checks. Claude runs
`--restricted` with read-only tools. govulncheck and Jelly run sandboxed. Model text in
package files is data, not instructions; a wrong `not_reachable` is the costly error, so
every model's `not_reachable` is held to a measured floor and, for weaker models, a second
read. Details: `docs/data-handling.md`, `docs/design.md`. Reporting: `SECURITY.md`.

## Docs

- `docs/design.md`: acceptance floors, cascade toggles, the jelly tier, the connect guard.
- `docs/data-handling.md`: dependency source, egress modes, call shapes.
- `docs/running.md`: backends, exploit signals, the harness, tests.

## Licence

Code: [Apache License 2.0](LICENSE) (see also [NOTICE](NOTICE)). Case data under `cases/`:
[CC-BY 4.0](cases/LICENSE.md), including OSV advisory text (CC-BY 4.0).
