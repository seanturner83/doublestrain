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
  - `local` / any named OpenAI-compatible endpoint (LM Studio, llama.cpp, Ollama, vLLM):
    a grep summary plus numbered source excerpts, one JSON-schema verdict, no tools.
    Endpoints never settle `reachable`; an off-network endpoint is refused unless it is
    https and `SSVC_<NAME>_ALLOW_CODE_EGRESS=1`.
  - `split`: claude reads only the dependency's verified source and writes a trigger
    spec; a local endpoint matches it against the app. App code stays on your machine.
  - `shape`: claude sees the dependency source plus abstracted call shapes from the app.
  - `claude`: `claude -p` in the checkout, read-only tools, `--restricted`.
  - `jev`: an optional hosted classifier (TypeSafe's Jev API; needs its own key).
- `src/ssvc_triage/feeds/`: CISA KEV and FIRST EPSS, cached (see "Exploit signals").
- `src/ssvc_triage/reach.py`: applies an accepted verdict to a candidate.
- `src/ssvc_triage/harness/`: `ssvc-run`, `ssvc-score`, `ssvc-compare`; `ssvc-scan`
  grades one repo; `ssvc-usage` summarises the model-call ledger.
- `cases/`: labelled apps. Each has `case.json`, plus `fetch.sh` for third-party checkouts.

## Malware bypasses the reachability gate

A malicious package version is not a vulnerability that code reaches. It runs at install time on every machine that installs it: dev machines, CI and production. An advisory counts as malware when any of these holds:
- an OSV `MAL-*` record (OpenSSF malicious packages) is among its IDs;
- it carries malicious-packages origin metadata;
- it is tagged CWE-506.

Such an advisory skips the judges and grades **Act**, whatever its exposure, EPSS or reachability. The scan digest flags it `MALWARE`.

**Suspected malware** covers advisories with none of those markers, typically a compromised release of a legitimate package filed as an ordinary advisory. Missing one is the expensive error: app code usually never imports a malicious package, so a reachability judge would rightly say not reachable, and the advisory could end up on Track.

`judges/malware.py` asks Jev one bounded question about **every** unmarked advisory: is it about a malicious or compromised package version, or about a vulnerability exploited with malicious *input*? Answers are cached by advisory text, so the steady state is one call per new advisory.

The narrow text pre-filter (phrases like "malicious code", "backdoor", "compromised version", "protestware", plus CWE-912) is not a gate. It only sets how much evidence Jev must give:

| Pre-filter | Suspected when |
|---|---|
| matches | unless Jev confidently says "vulnerability" (≥ `SSVC_MALWARE_CLEAR_FLOOR`, default 0.8) |
| no match | only if Jev confidently says "malicious package" (≥ `SSVC_MALWARE_FLAG_FLOOR`, default 0.8) |
| Jev unreachable | if and only if the pre-filter matches |

Suspected advisories skip the judges. They are graded on their other axes and **never fall below Attend**, flagged `SUSPECTED-MALWARE`.

Measured 2026-10-10:
- **Noise:** over 193 real unmarked OSV advisories, Jev called 192 confidently "vulnerability"; the other was below the flag floor. 0 suspected.
- **Catching:** 8 real incidents (ua-parser-js, event-stream, flatmap-stream, coa, rc, node-ipc, colors, eslint-scope) were reworded so that no pre-filter phrase matches. Jev flagged all 8 at 1.00. The earlier design, which only asked Jev about pre-filter matches, would have missed all 8.

## Acceptance is asymmetric

A wrong `not_reachable` hides a live risk, whereas a wrong `reachable` only costs triage
time. So each judge has two floors, `(reachable, not_reachable)`. They live in
`src/ssvc_triage/judges/floors.toml`: defaults per role, then an entry per model, keyed on
the model that actually answered (an endpoint's model id, split's matcher model, shape's
resolved claude model). Each entry records what it was measured on. A model with no entry
gets its role's defaults. Swapping the model behind an endpoint therefore doesn't
inherit another model's numbers.

| Role | Default floors (reachable, not_reachable) | Model entries |
|---|---|---|
| `jev` | (never, 0.9) | |
| `endpoint` (`local`, `workstation`, ...) | (never, 0.9), needs corroboration | qwen/qwen3.8-27b: (never, 0.9), needs corroboration |
| `jelly` | (never, 0.9), needs corroboration (an endpoint model counts) | |
| `split` | (never, 0.95) | qwen/qwen3.8-27b matcher: (never, 0.95) |
| `shape` | (never, 0.9) | claude-opus-5-5: (never, 0.85); claude-sonnet-5-5: (never, 0.9) |
| `claude` | (0.5, 0.7) | |

Override them with `SSVC_FLOOR_<TIER>_REACHABLE` / `SSVC_FLOOR_<TIER>_NOT_REACHABLE`
(tier name, e.g. `WORKSTATION`), or point `SSVC_FLOORS_FILE` at another file in the same
format. A verdict below its floor escalates (in a cascade) or leaves reachability
`unavailable`.

### Holding back a not_reachable (cascade toggles)

Two toggles stop a not_reachable that clears its floor from settling the row. Both are
on by default (since 2026-10-18: r6 and r7 gave 0 false not_reachable with them). A held
not_reachable is never returned: if no later tier settles the row, it stays unresolved.

- Disagreement escalation (off: `--no-escalate-disagreement`,
  `SSVC_ESCALATE_DISAGREEMENT=0`): a not_reachable that contradicts an earlier tier's
  `reachable` goes on to the next tier. The last tier settles as usual.
- Corroboration (off: `--no-corroborate`, `SSVC_CORROBORATE=0`): a not_reachable from a model marked
  `corroborate` settles only when a later tier in its `corroborate_by` roles (split,
  shape, claude) also accepts not_reachable. Another weak endpoint agreeing doesn't count.
  This is for a model whose confidence doesn't separate its right answers from its wrong
  ones, where a higher floor can't help. Qwen answers 0.90 or 0.95 and was wrong at both.
  `split` keeps app code on the machine (claude sees the advisory only), so under
  `--egress machine` corroboration costs tokens, not privacy.

all10 (1,045 rows, 941 labelled), `cascade:workstation,split:workstation,shape`:

| Run | False not_reachable | Coverage | Claude spend | Note |
|---|---|---|---|---|
| r4 | 7 | 0.657 | $8.81 | 348 rows lost to the usage limit |
| r5, `--escalate-disagreement` | 4 | 0.763 | $23.01 | no limit hits, so shape ran on every row |
| r6, + corroboration, Opus shape floor 0.85 | 0 | 0.650 | $22.89 | $20.23 of it one-off split specs |
| r7, + registry integrity fallback | 0 | 0.696 | $4.82 | the 96 no-integrity rows get a split answer |
| r9, + reaching parents become triggers | 0 | 0.747 | $1.97 | the connect guard's blanket holds lifted where a parent's route is checked |
| r10, `cascade:jelly,workstation,...` | 0 | 0.748 | $0 (all cached) | 170 rows settle at jelly + workstation; split/shape needed on 169 fewer rows |

r5's four misses: two workstation not_reachables on serve-static (corroboration holds
these), and two shape not_reachables at exactly 0.80 (the Opus shape floor is now 0.85:
on r5 that holds both and costs 20 correct rows).

### Which packages load at all: the `jelly` tier (npm)

`jelly` runs [Jelly](https://github.com/cs-au-dk/jelly) (static analysis, BSD-3-Clause)
once per checkout in `--modules-only` mode. It follows `require`/`import` from every
non-test app source file through a node_modules assembled from pkgsrc (verified tarballs,
source only, nothing installed), and answers at package level:

- the advisory's package (that installed copy) is loaded: `unsure`, with that in the
  rationale. Being loaded says nothing about the vulnerable function;
- it is never loaded and no guard fires: not_reachable 1.0, which needs a second read
  (floors.toml). The workstation model counts as one, and vice versa: a static
  analysis and a model fail in different ways. So `cascade:jelly,workstation,...` settles
  a row both agree on without a claude tier.

A static analysis misses loads it can't see. Each of these makes the answer `unsure`, for
the package and every package on its route from the app:

| Guard | Catches |
|---|---|
| a loaded package with a computed `require` declares a package on the route | sequelize loading its dialect driver (sqlite3 on sirappsec, the prototype's one miss) |
| the app names an unloaded route package in a string, config file, view-file extension, `node_modules/<name>` path or package.json field | `'view engine', 'pug'`, `client: 'pg'`, babel presets, jquery copied to `public/` |
| package.json scripts run it or preload it (`-r`) | `pm2 start` (pm2 really runs in production) |
| a computed `require` in the app, or an app file Jelly can't parse (it drops those silently, exit 0), and the route starts at a direct dependency | parse-server's `AdapterLoader` |
| a package on the route couldn't be fetched and verified, or lost files to size caps | |

Not covered: non-JS code (`.vue`/`.svelte` files are only searched for names), and
packages named by data outside the checkout (environment variables, a database).

Sandboxing: under macOS `sandbox-exec` Node has no network and writes only to the run's
directory. The analysis copy is deleted after each run. Jelly's dynamic (`-d`) and
`--approx` modes execute code and are never used.

Measured (2026-10-19, 0 false not_reachable in both):

| Set | Jelly not_reachable | Right / wrong | Guard-held, labelled | Loaded |
|---|---|---|---|---|
| all10 (guards designed here) | 230 rows (179 labelled) | 179 / 0; 0 of 97 reachable labels | 616 | 476 not_reachable labels, 97 reachable |
| held out: uptime-kuma, parse-server, jsbin | 7 | 7 / 0 | 44, all not_reachable | 408 of 452 rows |

The held-out apps load most of what they install, so Jelly settles little there; its
guards held 44 rows that turned out not_reachable (the cost of safety). On all10, against
r9's recorded answers, Qwen agrees with 170 of Jelly's 230: those rows would settle at the
workstation, without split or shape. Coverage barely moves (+1 row); the gain is claude
calls and time (seconds per app, $0).

### Why the summary tiers never settle `reachable`

`jev` and `local` see that the app uses a package. They don't see whether attacker input
reaches it, or whether an advisory's extra condition holds. Before this rule, their
accepted `reachable` calls were 4 right and 10 wrong across NodeGoat and DVWS-node:
- parsers fed only a server fixture file;
- globs that are app constants;
- options the app never sets.

Over the same advisories, every `not_reachable` they gave above the 0.9 floor was correct.
So their `reachable` now always escalates to claude. That costs roughly 2¢ per advisory, and
a wrong `reachable` only costs triage time. This replaced an earlier Jev precondition
check, which caught unmet options but not untrusted-input questions.

All cases (`cascade:jev,local,claude`, 185 advisories, 112 labelled), 2026-10-11:

| Case | Settled by jev / local / claude | False not_reachable | False reachable |
|---|---|---|---|
| fixtures + adversarial + vlb | 4 / 2 / 15 (1 unresolved) | 0 | 0 |
| real-nodegoat (17 labelled) | 0 / 1 / 16 | 0 | 2 |
| real-dvws-node (73 labelled, blind) | 5 / 21 / 47 | 0 | 1 |

The 3 remaining errors are claude's. They are false `reachable` calls at 0.80-0.95 that
contradict my labels:
- NodeGoat body-parser CVE-2024-45590 (`extended:false`);
- NodeGoat send CVE-2024-43799 (serve-static's directory listener);
- DVWS apollo-server-core GHSA-9q82-xgwf-vj6h (Apollo Server 3 CSRF prevention is opt-in).

I checked all three labels against the exact tarballs in the lockfiles (integrity hashes
matched), and all three hold. Claude reasoned about library internals it couldn't read,
because `node_modules` isn't in the checkout, so it answered from memory.

## Dependency source for the claude judge (`SSVC_PKGSRC=1`)

The 3 errors above share one cause: claude answered library-internals questions from
memory. With `SSVC_PKGSRC=1`, `pkgsrc.py` fetches the exact published versions the
lockfile pins:
- the vulnerable package;
- every package that directly depends on it;
- the rest of the shortest chain, up to 4 packages in all.

They are added to the claude judge read-only (`--add-dir`), and the extra system prompt
tells claude to check behaviour there and cite it. Only npm is supported, and the jev and
local tiers never see this source.

These packages are untrusted, possibly vulnerable and possibly malicious, so they are
handled as hostile bytes. **Nothing is installed or executed.**

| Threat | Control |
|---|---|
| Tampered or substituted tarball | Integrity is checked before parsing. A lockfile `sha512` must match. A sha1-only entry (old npm) must match **and** match the registry's sha512 for that exact version. An entry with no integrity at all (old lockfiles) must match the registry's sha512 for that exact version (see below). |
| SSRF / arbitrary download | Only `SSVC_PKGSRC_REGISTRY` (default `https://registry.npmjs.org`) is contacted, https only, with no redirects. The URL is built from a validated name and version, never from the lockfile's `resolved`. |
| Path traversal | Absolute, `..`, drive-letter, backslash or control-character member names reject the whole package. |
| Links and special files | Symlinks, hardlinks, devices and FIFOs are skipped. Files are created `O_EXCL\|O_NOFOLLOW` in a fresh staging dir, then renamed into place. |
| Executable content | Only JS/TS source and JSON are kept, with no native addons and no README text. Files are made `0444`, so the exec and setuid bits are dropped. No lifecycle script ever runs. |
| Decompression bombs | Caps: 25 MiB compressed, 150 MiB inflated, 20k members, 2 MiB per file, 60 MiB written. |
| Prompt injection in package text | `--restricted` confines Read/Grep/Glob to the checkout plus these dirs, and claude has no Bash or web tools. Injected text can't read or send anything else, and the system prompt marks the source as data. Malware and suspected malware skip the judges, so they are never fetched. |

The residual risk is that injected text skews a verdict. It can't read or send anything,
but a forced wrong `not_reachable` is the expensive direction.

The confinement test (2026-10-12) put a canary file outside the checkout. Under the old
flags, the judge's Read returned it. Under `--restricted`, direct paths, `..`, symlinks
(file and dir) and Grep were all refused, while `--add-dir` paths were readable. So
`--restricted` now applies to every claude call, not just pkgsrc ones.

### Verified dependency trace

With source provided, claude's answer gains `dependency_trace`: `[{path, line, quote}]`,
where `path` is `<name@version>/<file>`. `check_trace` verifies each step mechanically:
- the path must resolve inside a provided source directory, with no escapes;
- the quoted code must appear (whitespace-normalised) within 2 lines of the cited line.

A `reachable` verdict needs at least one verified step inside the vulnerable package.
Otherwise claude is retried once and told exactly what failed. A second failure becomes
`unsure`. `reachable` and unresolved grade identically, so this withdraws only the claim.
`not_reachable` isn't trace-checked: "the package is unused" needs no dependency step.

Results, 2026-10-12, claude-only over all 90 labelled advisories in NodeGoat and DVWS-node:

| Set | Without source | With source + trace |
|---|---|---|
| held out (83) | 83 right, 0 false NR | 83 right, 0 false NR |
| tuning set (the 7 above) | 4 right, 3 false R | 6 right, 1 false R |

- **Held out:** claude was already right on all 83 without source. So this measures only
  that nothing regressed, in particular no new false `not_reachable`. It shows no benefit.
- **Fixed:** send and apollo-server-core, both on the first answer. Asking for a trace was
  enough; the retry wasn't needed.
- **Every `reachable`:** all 9 carried verified steps. The one retry, qs CVE-2022-24999,
  traced express → qs and correctly stayed `reachable`.
- **Still wrong:** body-parser. Claude cited `urlencoded.js:43`, the parser's entry point,
  which is a real line, so it passed. The check proves claude opened the package, not that
  the trace reached the vulnerable code (the qs `extended` parser).
- **Cost:** $2.83 for the 90-advisory pass.

Sources are cached in `SSVC_PKGSRC_CACHE` (default `~/.cache/ssvc-triage/pkgsrc`), with a
manifest (`<dir>.json`) recording the URL, what was verified and what was skipped. Only
package names and versions leave the machine, as with OSV. Answers given with source are
cached separately (`@src<id>` in the fingerprint).

## Before and during a run

- **Tier check:** `ssvc-scan` and `ssvc-run` probe every tier first and print which are
  down and where their questions will escalate. `--require-tiers` refuses to run if any
  tier is down.
- **Claude budget:** `--claude-budget USD` (scan default 5) stops claude calls once that
  much is spent. Anything left over stays unresolved, which grades like `reachable`. So a
  dead local tier can no longer quietly turn a free re-run into a claude bill.
- **Parallel rows:** `--workers N` (on `ssvc-run` and `ssvc-scan`) judges N rows at
  once; each row's cascade still runs in order, and results are written in input order.
  It pays off when an endpoint serves parallel requests (LM Studio: parallel slots with
  the unified KV cache off, and a context big enough for every slot: about 12-16k tokens
  each for split matches). `--claude-workers N` caps concurrent claude calls separately
  (the session limit is shared across the account). Rows that need the same spec,
  govulncheck scan, package or cached answer wait for the first one instead of repeating it.
- **Usage limit:** the claude.ai session limit is shared across the account. On a limit,
  `ssvc-run` sleeps until the reset time in the message (plus 2 minutes, at most 6 hours)
  and retries. `--no-wait-on-limit` (or `SSVC_CLAUDE_WAIT_ON_LIMIT=0`) leaves the row
  unresolved instead.
- **Usage ledger:** every model call (claude and endpoint) appends one line to
  `SSVC_ACCOUNTING_LOG` (default `~/.cache/ssvc-triage/accounting.jsonl`, mode 0600;
  `off` disables). A line is tagged with the tool, run, case, CVE, package and purpose
  (spec, shape, judge, match, defeat, triage), and records the model, outcome, cost,
  tokens (including cache reads), latency and claude's session id. No prompt or answer
  text is written. Cached answers make no call and aren't recorded.
  `ssvc-usage --since 24h --by tool,purpose,model` summarises it, and `ssvc-run` prints
  its own totals and keeps them in `summary.json`.

## What leaves the machine

| Flow | Sends | First-party (app) code? |
|---|---|---|
| OSV, npm registry (`--pkgsrc`) | package names and versions | no |
| KEV / EPSS | CVE ids | no |
| Jev malware check | advisory text, package name | no |
| Jev reachability tier (hosted, **or via Jevstiller**, which forwards to hosted Jev upstream) | grep summary quoting app source lines (up to 1500 chars) | **yes** |
| `jelly` | nothing (it uses pkgsrc: package names and versions) | no |
| `local` / LAN endpoints | source excerpts | stays on your network |
| off-network endpoints (opt-in) | source excerpts | **yes** |
| `claude -p` (Anthropic API) | whatever it reads in the checkout | **yes** |

So the default cascade does **not** keep first-party code on your own machines. The
opt-in egress modes below do.

### Egress modes (`--egress`, `SSVC_APP_CODE_EGRESS`)

| Mode | App code may go to | Allowed tiers |
|---|---|---|
| `any` (default) | anywhere | all |
| `shape` | source: your network; abstracted call shapes: offsite | as `network`, plus `shape` |
| `network` | this machine or your private network | `local`, LAN endpoints, `split` |
| `machine` | this machine only | `local` (loopback), `split` with a loopback matcher |

`get_judge` checks every tier's destination before anything runs and refuses with
`--egress X forbids: …`. Destinations: `jev` and `claude` are offsite (Jevstiller forwards
upstream); an endpoint is machine, network or offsite by its resolved address.

The **`split`** tier is what makes the strict modes useful. It splits the question in two:

1. **Trigger spec (off-machine, third-party input only).** `claude -p` runs with cwd = the
   verified source of the vulnerable package (`pkgsrc`), with its dependents added via
   `--add-dir` and no app checkout. It lists the public entry points, option conditions and
   inputs that reach the vulnerable code, each with a verified trace. Triggers without a
   verified step in the target package are dropped. The spec depends only on the advisory
   and package versions, so it is cached (`~/.cache/ssvc-triage/triggers`) and reused for
   every app.
2. **App match (on-machine).** The `local` endpoint (or `split:<endpoint>`) answers a
   bounded question over app excerpts around the spec's entry points: does the app call one
   with the condition met? The usual open-world guard applies. Like the other summary
   tiers, it settles only `not_reachable`, and only at confidence 0.9 or above.

Measured on real-nodegoat and real-dvws-node (162 advisory rows, 82 labelled
`not_reachable`):

| | default `cascade:jev,local,claude` | `--egress machine`, `cascade:local,split` |
|---|---|---|
| false `not_reachable` | 0 | 0 |
| rows settled `not_reachable` | 143 | 84 |
| labelled `not_reachable` settled | 79 / 82 | 40 / 82 |
| claude spend | ~$2.8 | $4.2 to build 111 specs, then about $0 when they are reused |

Strict mode is safe, with no false settlements, but it settles about half as much. The rest
stays unresolved and grades as exposure decides (Attend rather than Track). The 0.9 floor
holds: 19 split `not_reachable` answers fell below it, and 2 of those were labelled
`reachable`. Where the lockfile has no integrity (old NodeGoat `tar` entries), specs now
use the registry fallback below.

#### Lockfile entries with no integrity: the registry fallback

Old lockfiles often record no `integrity` for a package. Without a hash there is nothing
to check a download against, so pkgsrc used to refuse it, and split and shape had no
dependency source to work from. In all10-r6 that left 68 rows with no second read, which
corroboration then had to leave unresolved.

By default (`SSVC_PKGSRC_REGISTRY_INTEGRITY=1`), such a package is checked against the
registry's own sha512 for that exact name and version, fetched from the same registry
(https, no redirects). A sha1-only registry entry isn't enough, and a mismatch refuses
the package. What this proves is weaker than a lockfile hash: the bytes are what the
registry publishes for that version, not necessarily what this app installed. npm doesn't
let a published version's tarball change, which narrows that gap. Each fetched package's
cache manifest records what verified it (`"verified": {"lockfile": [], "registry":
["sha512"], "registry_only": true}`). Only the package name and version leave the machine.

`--no-registry-integrity` (on `ssvc-run` and `ssvc-scan`) or
`SSVC_PKGSRC_REGISTRY_INTEGRITY=0` turns the fallback off: entries with no integrity are
refused again, even if a copy is already cached.

### Call shapes (`--egress shape`, the `shape` tier)

`split` keeps every byte of app code local, and its on-machine matcher is the weak link.
`shape` sends claude a little more: a **mechanically derived**, abstracted list of how the
app calls the vulnerable package and the packages that depend on it. No model touches the
app before egress. A deterministic tokenizer and parser (`judges/shape.py`) emits only:

- callees resolved to package paths (`express().use`, `new @xmldom/xmldom.DOMParser().parseFromString`)
  or a conventional receiver (`res.sendFile`, `<obj>.x`);
- literal numbers, booleans and null, and strings only when short and identifier-like
  (`"utf-8"`, `"allow"`; `SSVC_SHAPE_STRINGS=none` redacts them all); object keys;
- markers `<request.body>`, `<env>`, `<dirname>`, `<var>`, `<fn>`, `<call>` and `<expr>`,
  plus where the call sits (`arg of` / `in fn passed to express().get`);
- for variables and parameters, the sources of their values: `<var from request.query>`,
  `<var from file>`, `<var from literal, request.body>`, or `other` for anything not
  tracked. Taint follows assignments, calls to helpers (argument to parameter), modules
  (`require('./x')` / `import`), and route handlers, including renamed `(r, s)` parameters
  and controllers passed by reference (`router.post('/n', ctl.create)`);
- pseudonymous file ids (f1, f2, …).

Function bodies, comments, other identifiers, paths and line numbers never leave.
`ssvc-shapes REPO PACKAGE...` prints exactly what would be sent. For DVWS:

```
s7  [f3]  express().use(body-parser.urlencoded({extended: true}))
s9  [f3]  express().use(express-fileupload({parseNested: true}))
s8  [f2]  xml2js.Parser().parseStringPromise(<var from request.body>)
s6  [f1]  new @xmldom/xmldom.DOMParser().parseFromString(<var from file>)
```

claude runs as for the trigger spec: cwd = the verified package source, with no app
checkout. It gets the cached spec, the shapes and the coverage facts. `shape` is a summary
tier, and a truncated shape list can't settle `not_reachable`.

Same apps, `cascade:local,split,shape --egress shape` (local and split answers from cache):

| | default | `machine` (`local,split`) | `shape` (`local,split,shape`) |
|---|---|---|---|
| false `not_reachable` | 0 | 0 | 0 |
| rows settled `not_reachable` | 143 | 84 | 99 |
| labelled `not_reachable` settled | 79 / 82 | 40 / 82 | 54 / 82 |
| claude spend | ~$2.8 | $4.2 of specs, built once | + $0.9 for 68 shape calls |

With value-source tracking (extractor v3), shape settled 99 rows, up from 96 without it,
and the 4 `reachable` answers it gave at 0.9 are all labelled `reachable`. It is still
cautious: 24 `not_reachable` answers stayed below 0.9, and one of those is labelled
`reachable`, so the floor stays.

**Model and refusals.** The shape question runs on `SSVC_SHAPE_MODEL` (default `opus`).
If Opus refuses, it falls back to `SSVC_SHAPE_FALLBACK` (default `sonnet`). Specs stay on
`SSVC_CLAUDE_MODEL`, so they are shared with `split`. A refusal is never an answer. These
all count as refusals: a refusal stop reason, a safety stop, a usage-policy error, or
refusal wording with no schema answer. On a refusal, the same question goes to the next
model. If every model refuses, there is no claim, and nothing is cached. The rationale
records who refused and which model answered (taken from `modelUsage`).
`SSVC_CLAUDE_FALLBACK` gives the claude tier and the specs the same fallback chain
(default: none).

Opus vs Sonnet on the shape question, same shapes and specs (68 calls each):

| shape model | `not_reachable` at >= 0.9 / >= 0.85 / >= 0.8 | of those, labelled `reachable` | rows settled | cost |
|---|---|---|---|---|
| Sonnet | 15 / 24 / 34 | 0 / 1 / 1 | 99 | $0.92 |
| Opus | 6 / 29 / 42 | 0 / 0 / 0 | 90 | $2.38 |

There were no refusals in 66 Opus calls. Opus says `not_reachable` more often and more
correctly than Sonnet (with fewer `unsure`), but it reports lower confidence (mostly
0.8 to 0.88), so at the shared 0.9 floor it settles less. Its one `not_reachable` on a
`reachable` label was below 0.8. Opus now has its own floor (floors.toml): 0.8 after the
six-app run, raised to 0.85 after all10-r5 (at 0.80: 20 right, 2 wrong; at >= 0.85: 135
right, 0 wrong).

## Backends

| Judge | Needs |
|---|---|
| `jev` | `TYPESAFE_API_KEY`, or a key file at `TYPESAFE_API_KEY_FILE` (default `~/.keys/jev.key`). Note: with the key file present and `TYPESAFE_BASE_URL` unset, calls go to the **hosted** Jev API. Its answers differ from the local student's, and the cache keeps the two apart. Jevstiller is optional: `TYPESAFE_BASE_URL=http://localhost:8080` routes calls through the local proxy and student; without it, calls go to the hosted API. |
| `local` / `<name>` | `SSVC_LOCAL_BASE_URL` (default `http://localhost:1234/v1`), `SSVC_LOCAL_MODEL` (default: the server's first listed model), optional `SSVC_LOCAL_API_KEY`, `SSVC_LOCAL_TIMEOUT` (default 180), `SSVC_LOCAL_CONTEXT_CHARS` (default 24000). |
| `shape` | `claude`, pkgsrc (specs shared with `split`). `SSVC_SHAPE_STRINGS=none` redacts all string literals. |
| `jelly` | npm only. Node >= 22 and Jelly 0.13 under `SSVC_JELLY_HOME` (default `~/.cache/ssvc-triage/jstools`: `npm install --ignore-scripts @cs-au-dk/jelly` there), `SSVC_PKGSRC=1`. `SSVC_JELLY_HEAP_MB` (default 8192), `SSVC_JELLY_TIMEOUT` (default 1200), `SSVC_JELLY_WORK` (analysis copies, removed after each run). |
| `split` / `split:<endpoint>` | `claude` (for specs, with pkgsrc) plus the matcher endpoint (default `local`). `SSVC_SPEC_CACHE` moves the spec cache. |
| `claude` | `claude` on PATH, logged in. `SSVC_CLAUDE_MODEL` (default `sonnet`), `SSVC_CLAUDE_TIMEOUT` (default 300), `SSVC_PKGSRC=1` to add dependency source. |

## Exploit signals

`--enrich` on `ssvc-run` and `ssvc-scan` picks the source:

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
uv run ssvc-run --judge null                 # baseline: no reachability for non-Go
uv run ssvc-run --judge jev
uv run ssvc-run --judge claude
uv run ssvc-run --judge local
uv run ssvc-run --judge cascade              # == cascade:jev,claude
uv run ssvc-run --judge cascade:jev,local,claude
uv run ssvc-run --judge cascade --enrich live  # real KEV/EPSS instead of fixture values
uv run ssvc-run --judge cascade --case npm-js-yaml-config-driven --no-cache
uv run ssvc-compare runs/<A> runs/<B>
uv run ssvc-score runs/<A>
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
