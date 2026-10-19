# Data handling: dependency source, egress and call shapes

What is fetched, how untrusted package bytes are handled, and what leaves the machine in each egress mode. See the [README](../README.md) for the overview.

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
