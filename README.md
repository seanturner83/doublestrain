# doublestrain

*Double straining: pouring a cocktail through the Hawthorne strainer and a fine strainer at
once, so nothing gets into the glass that shouldn't. Here, an advisory is set aside as
"not reachable" only after it has been through two independent reads.*

Grades dependency advisories (from a lockfile scan, or Dependabot bumps) into SSVC's
**Act / Attend / Track**, using whether the vulnerable code is actually reachable in your
app. Models supply that reachability fact with evidence; a fixed decision tree
(`ssvc.py`) makes the call, from three facts: exploitation (CISA KEV, FIRST EPSS),
reachability and exposure. Every fact records where it came from (`reach_source`), and
model verdicts only count when they clear acceptance floors measured against labelled
apps (`judges/floors.toml`). A wrong "not reachable" hides a risk, so that direction is
held to the stricter standard throughout.

What's in the box:

- `src/doublestrain/ssvc.py`: the decision tree (`grade`, `grade_all`).
- `src/doublestrain/osv.py`, `cargo.py`, `gomod.py`, `pylock.py`: lockfiles (npm, pip,
  Cargo, Go) to OSV advisories to candidates. `sweep.py`: sweep JSONL records to
  candidates; the exposure map.
- `src/doublestrain/imagedeps.py`, `approots.py`: what the app's Dockerfile installs and
  builds counts as production (Python groups and extras, local projects, `cargo build`
  lines), whatever the group or file is called.
- `src/doublestrain/cargofeat.py`: Cargo feature resolution over the manifests, so a
  locked crate the deployed binary never compiles (an optional dependency no enabled
  feature turns on, a Windows-only target) is known as such.
- `src/doublestrain/jvmjars.py`, `jvmcallers.py`: JVM apps don't commit lockfiles, so the
  deployed classpath is read from the released artifact (a distribution tarball or zip, a
  fat jar, a war): every jar's Maven coordinates, checked against Maven Central's sha1.
  `jvmcallers` builds a call graph from the release's bytecode and walks back from the
  advisory's classes to the app's own code, so a trigger inside a library the app calls
  is visible to the judges.
- `src/doublestrain/names.py`: one rule per ecosystem for "is this the same package?"
  (PEP 503, Cargo's `-`/`_`, Maven `group:artifact`).
- `src/doublestrain/judges/`: the reachability tiers, run as a cascade
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
- `src/doublestrain/feeds/`: CISA KEV and FIRST EPSS, cached (`docs/running.md`, "Exploit signals").
- `src/doublestrain/reach.py`: applies an accepted verdict to a candidate.
- `src/doublestrain/harness/`: `doublestrain run`, `doublestrain score`, `doublestrain compare`;
  `doublestrain scan` grades one repo; `doublestrain usage` summarises the model-call
  ledger. `doublestrain --help` lists every command; each is also installed as
  `ssvc-<command>`. Configuration is `SSVC_*` environment variables, caches live under
  `~/.cache/ssvc-triage`.
- `cases/`: labelled apps. Each has `case.json`, plus `fetch.sh` for third-party checkouts.

## Quickstart

```sh
uv sync
# grade one app's dependency advisories (OSV + KEV/EPSS); no reachability judge:
uv run doublestrain scan path/to/app --judge null --exposure public-internet
# with judges: local/LAN models first, claude only on what they can't settle,
# app source never leaving your network except as abstracted call shapes
export SSVC_PKGSRC=1 SSVC_WORKSTATION_BASE_URL=http://<your-llm-host>:1234/v1
uv run doublestrain scan path/to/app --egress shape \
    --judge cascade:jelly,workstation,split:workstation,shape
# a JVM app: point it at the release it ships (its jars are the classpath)
uv run doublestrain scan path/to/checkout --artifact path/to/app-1.2.3.tar.gz \
    --first-party org.example --judge cascade:workstation,split:workstation,claude
```

`doublestrain scan` writes `runs/scan-<ts>-<name>/` with a digest (Act first), every grade with
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
`split` 128 right, 0 wrong.

Python, Rust and JVM apps, labelled blind (each set's disputed labels re-read and decided
2 of 3). The pair is `split` (Claude spec, local matcher) with `claude` (Opus) agreeing on
the `not_reachable`; coverage is the share of `not_reachable` labels it settles:

| Set | Apps / rows | Pair right / wrong | Coverage |
|---|---|---|---|
| Python held-out (py8) | 5 / 564 | 260 / 0 | 0.560 |
| Rust dev (rs1) | 5 / 283 | 159 / 0 | 0.624 |
| Rust held-out (rs2) | 5 / 320 | 155 / 1 | 0.596 |
| Rust held-out (rs3) | 5 / 344 | 166 / 0 | 0.574 |
| JVM dev (jv1, published cases) | 4 / 422 | 130 / 2 | 0.369 |
| JVM (jv2, published cases) | 3 / 288 | 100 / 1 | 0.395 |
| JVM jv2 after the call-graph fixes, split >= 0.90 | 3 / 288 | 178 / 0 | 0.704 |

pip and Cargo now settle as that pair only; Maven is still held for every tier until a
held-out set on the current code. Three JVM cases from these sets are not published yet,
so the JVM rows above count only the published ones. Every change and its measurement is
in `docs/design.md`.

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
  registry / Go proxy / crates.io / PyPI / Maven Central get names and versions (Maven
  Central also serves the published `.pom` and `-sources.jar` for identified jars). What each judge tier sends is in
  `docs/data-handling.md`.

## Limitations

- **Small benchmarks.** Floors and results come from ten npm apps (most built to be
  vulnerable), three held-out npm apps labelled only where the Jelly check needed it, five
  Go apps, and five-app Python, Rust and JVM sets of real self-hosted software. Real
  codebases will hit cases these don't.
- **AI-made labels** (see "Labels and data"): measured error rates are agreement with
  them.
- **Ecosystems differ in how far they are measured.** npm: every tier. Go: govulncheck
  and `split` measured. pip and Cargo: `split` with `claude` agreeing (see Results); every
  other tier's `not_reachable` is held there. Maven: held for every tier
  (`SSVC_NR_UNMEASURED`) until a held-out set on the current code.
- **JVM inventory needs the release.** A checkout alone doesn't say which jars ship, so
  `--artifact` takes the distribution, fat jar or war the app releases. Jars are
  identified by their embedded coordinates or a Central sha1 match; a rebuilt jar is kept,
  marked unverified. The bytecode call graph is a class-hierarchy approximation: reflection
  and framework dispatch by name are not followed, so "no caller found" is evidence, not
  proof.
- **Jelly's held-out sample is small:** 7 `not_reachable` rows on three apps (all right),
  so it settles nothing without a second read. It does not see non-JavaScript code
  (`.vue`/`.svelte` files are only searched for package names) or packages named by data
  outside the checkout. Its sandbox is macOS `sandbox-exec`; elsewhere it runs unsandboxed
  (static analysis, but still parsing untrusted code).
- **Models vary run to run:** the measured local model changed about 9% of its answers
  between two runs at temperature 0. That is one reason a weak model's `not_reachable`
  needs a second read.
- **Prompt injection** in package source can try to steer a model's verdict. Tools are
  read-only and confined, clearances need checked evidence, and weak models need a second
  read, but a forced wrong `not_reachable` remains the residual risk.
- **Exposure is an input.** Without `--exposure`, an app is `unknown`, which grades
  conservatively; the tool doesn't discover how an app is deployed.

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
