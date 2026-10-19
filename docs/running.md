# Running it: backends, feeds, the harness

See the [README](../README.md) for the overview.

## Before and during a run

- **Tier check:** `doublestrain scan` and `doublestrain run` probe every tier first and print which are
  down and where their questions will escalate. `--require-tiers` refuses to run if any
  tier is down.
- **Claude budget:** `--claude-budget USD` (scan default 5) stops claude calls once that
  much is spent. Anything left over stays unresolved, which grades like `reachable`. So a
  dead local tier can no longer quietly turn a free re-run into a claude bill.
- **Parallel rows:** `--workers N` (on `doublestrain run` and `doublestrain scan`) judges N rows at
  once; each row's cascade still runs in order, and results are written in input order.
  It pays off when an endpoint serves parallel requests (LM Studio: parallel slots with
  the unified KV cache off, and a context big enough for every slot: about 12-16k tokens
  each for split matches). `--claude-workers N` caps concurrent claude calls separately
  (the session limit is shared across the account). Rows that need the same spec,
  govulncheck scan, package or cached answer wait for the first one instead of repeating it.
- **Usage limit:** the claude.ai session limit is shared across the account. On a limit,
  `doublestrain run` sleeps until the reset time in the message (plus 2 minutes, at most 6 hours)
  and retries. `--no-wait-on-limit` (or `SSVC_CLAUDE_WAIT_ON_LIMIT=0`) leaves the row
  unresolved instead.
- **Usage ledger:** every model call (claude and endpoint) appends one line to
  `SSVC_ACCOUNTING_LOG` (default `~/.cache/ssvc-triage/accounting.jsonl`, mode 0600;
  `off` disables). A line is tagged with the tool, run, case, CVE, package and purpose
  (spec, shape, judge, match, defeat, triage), and records the model, outcome, cost,
  tokens (including cache reads), latency and claude's session id. No prompt or answer
  text is written. Cached answers make no call and aren't recorded.
  `doublestrain usage --since 24h --by tool,purpose,model` summarises it, and `doublestrain run` prints
  its own totals and keeps them in `summary.json`.

## Backends

| Judge | Needs |
|---|---|
| `jev` | `TYPESAFE_API_KEY`, or a key file at `TYPESAFE_API_KEY_FILE` (default `~/.keys/jev.key`). Note: with the key file present and `TYPESAFE_BASE_URL` unset, calls go to the **hosted** Jev API. Its answers differ from the local student's, and the cache keeps the two apart. [Jevstiller](https://github.com/tomerglick57/Jevstiller) (Apache-2.0; distils the repeated Jev task into a local model) is optional: `TYPESAFE_BASE_URL=http://localhost:8080` routes calls through the local proxy and student; without it, calls go to the hosted API. |
| `local` / `<name>` | `SSVC_LOCAL_BASE_URL` (default `http://localhost:1234/v1`), `SSVC_LOCAL_MODEL` (default: the server's first listed model), optional `SSVC_LOCAL_API_KEY`, `SSVC_LOCAL_TIMEOUT` (default 180), `SSVC_LOCAL_CONTEXT_CHARS` (default 24000). |
| `shape` | `claude`, pkgsrc (specs shared with `split`). `SSVC_SHAPE_STRINGS=none` redacts all string literals. |
| `jelly` | npm only. Node >= 22 and Jelly 0.13 under `SSVC_JELLY_HOME` (default `~/.cache/ssvc-triage/jstools`: `npm install --ignore-scripts @cs-au-dk/jelly` there), `SSVC_PKGSRC=1`. `SSVC_JELLY_HEAP_MB` (default 8192), `SSVC_JELLY_TIMEOUT` (default 1200), `SSVC_JELLY_WORK` (analysis copies, removed after each run). |
| `split` / `split:<endpoint>` | `claude` (for specs, with pkgsrc) plus the matcher endpoint (default `local`). `SSVC_SPEC_CACHE` moves the spec cache. |
| `claude` | `claude` on PATH, logged in. `SSVC_CLAUDE_MODEL` (default `sonnet`), `SSVC_CLAUDE_TIMEOUT` (default 300), `SSVC_PKGSRC=1` to add dependency source. |

## Exploit signals

`--enrich` on `doublestrain run` and `doublestrain scan` picks the source:

| Mode | Source |
|---|---|
| `fixture` (default) | The cases' `enrichment` blocks, or `SSVC_ENRICH_MAP` for the runner. Offline and reproducible. |
| `live` | CISA KEV catalogue + FIRST EPSS, refreshed when older than `SSVC_FEED_MAX_AGE_H` (default 24). |
| `cache-only` | The feed cache only, with no network calls. Anything missing is unknown. |

- The cache lives in `SSVC_FEED_CACHE` (default `~/.cache/ssvc-triage/feeds`).
- EPSS requests are batched, and CVEs with no score are cached as **unknown** (`epss: null`), never 0.
- A failed refresh falls back to the stale cache, and the run's `summary.json` records the catalogue version, score dates and freshness.
- Only CVE IDs are sent to the feeds.

## Harness

```sh
uv run doublestrain run --judge null                 # baseline: no reachability for non-Go
uv run doublestrain run --judge jev
uv run doublestrain run --judge claude
uv run doublestrain run --judge local
uv run doublestrain run --judge cascade              # == cascade:jev,claude
uv run doublestrain run --judge cascade:jev,local,claude
uv run doublestrain run --judge cascade --enrich live  # real KEV/EPSS instead of fixture values
uv run doublestrain run --judge cascade --case npm-js-yaml-config-driven --no-cache
uv run doublestrain compare runs/<A> runs/<B>
uv run doublestrain score runs/<A>
```

Each run writes `runs/<ts>-<judge>/results.jsonl`, `summary.json` and `digest.txt`.
Decisions are scored against an **oracle**: the same tree graded with the labelled
reachability. The headline metric is **FALSE NOT-REACHABLE**. Next to it the summary
reports coverage, accuracy on resolved candidates, escalation rate, latency and cost.

A case is `cases/<id>/case.json` plus the app checkout:

```json
{"id": "...", "repo": "repo", "exposure": "public-internet",
 "enrichment": {"CVE-...": {"kev": false, "epss": 0.2}},
 "candidates": [{"kind": "keep", "pr": "local/<id>#1",
   "facts": {"package": "...", "ecosystem": "npm", "advisories": [["CVE-..."], ["<pkg>"]],
             "vuln_symbols": ["..."], "advisory_summary": "...", "import_name": "..."},
   "expect": {"reachability": "reachable|not_reachable", "note": "..."}}]}
```

The enrichment values in the shipped cases are **fixture signals**, not live KEV/EPSS data.

Shipped cases:
- 11 small fixture apps (`npm-*`, `pypi-*`).
- `vlb-1kQQfmmd`: `@cypress/request` 2.88.11 from vuln-bench, with six real dependency advisories (form-data, qs, uuid) taken from the 2026-10-05 scanner runs. Because it is a library, "reachable" means the library's own code exercises the vulnerable path under default options.

## Tests

`uv run python -m pytest -q` runs fully offline, using a fake Jev server and a fake `claude` binary.
