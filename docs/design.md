# Design: how a reachability fact is accepted

How judges' verdicts become facts the SSVC tree may use, and the guards that hold a `not_reachable` back. See the [README](../README.md) for the overview.

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
`src/doublestrain/judges/floors.toml`: defaults per role, then an entry per model, keyed on
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

### The connect guard, and evidence for "doesn't reach"

A spec describes the vulnerable package's entry points; the app may reach it through a
parent instead (mongoose -> mongodb -> bson). Before split or shape settles
not_reachable, the connect guard checks every route package the app imports: the spec
must give it a trigger or clear it in `parents` ("doesn't reach"), or the answer is
`unsure` (`SSVC_SPLIT_CONNECT_GUARD=0` turns the guard off).

Since 2026-10-19 a clearance counts only when it is backed. A clearance is a model's word
about third-party code, and injected package text could steer it:

- backed by the source: the parent never imports another route package, and has no
  computed `require` (`split.route_uses`);
- otherwise a follow-up read (purpose `spec-clears`, once per advisory, saved in the
  spec) must cite every file where the parent imports the route. Each citation is
  checked against the file. If the read now says the parent reaches, with a checked
  step, the parent becomes a via-parent trigger.

Cached split/shape not_reachables are rechecked under the current guard when read
(`recheck`), so a stricter guard needs no new matcher calls. On r10's answers, 460 of the
685 rows split/shape settled not_reachable stay settled; 225 rest on an unbacked
clearance and wait for that follow-up read on the next run (186 calls).

### Known gaps in advisory text (`advisory_notes.toml`)

Some advisories describe their own scope too narrowly, and a reader following the text
rules apps out wrongly: CVE-2024-43800 says it needs untrusted input passed to
`redirect()`, but serve-static redirects by itself on directory requests; CVE-2025-69223
describes aiohttp's server, but the same decompression runs in its client. The register
`src/doublestrain/advisory_notes.toml` records such gaps, and every tier sees a matching
note after the advisory summary (only those rows get a new cache key).

- Notes only widen: the loader refuses `kind` other than `widens` and note text that
  reads as a narrowing ("not affected", "only when", ...). A wrong widening note costs
  triage time; a narrowing one would hide a risk.
- Each note cites the named version's source (`path`, `line`, `quote`);
  `doublestrain advisories check` fetches it (registry-verified) and checks every step.
- File the correction upstream too (`upstream`); once the advisory is fixed, the entry goes.
- Entries come from label reviews on the benchmark apps, so their effect is measured on
  held-out apps. `SSVC_ADVISORY_NOTES=none` turns the register off.

### Which installed copy

When several versions of a package are installed, the usage pre-pass (and shape's
prompt) lists each copy, the packages that require it, and which copy a bare import in
the app loads. App import sites are evidence only for that copy. The 2026-10-18 label
review found the models' commonest error was reasoning about the wrong copy. Only rows
with a note (579 of 1,497 npm rows) get a new cache key.
