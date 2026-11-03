# Changelog

## Unreleased

- **Cases:** four held-out JVM apps (Apache ActiveMQ, Guacamole, James, Metabase; 261 rows,
  blind-labelled, disputed labels re-read 2 of 3). The Maven pair: 131 right, 0 wrong, with
  the gadget rule (README, Results).

## 0.2.1 (2026-11-02)

- **Fix: Maven settled almost nothing in 0.2.0.** A guard downgraded split's `not_reachable`
  to `unsure` whenever the app loads any class by a computed name (`Class.forName`,
  `loadClass`, `ServiceLoader.load`), and nearly every JVM app does: on a held-out set of
  five JVM apps it caught 218 of ~230 split `not_reachable` answers, so the Maven pair
  rarely ran. The pair's measurements never met the guard (the ecosystem hold was checked
  first while they ran), so the numbers in the README stand; the code now matches them.
  The guard is skipped where split's `not_reachable` needs the code-reading `claude`
  judge to agree anyway (pip, Cargo, Maven) and stays for a single read. Cargo was
  unaffected (the guard has no Rust patterns); pip's guard only looked at files importing
  the package, so it caught fewer rows there.
- **JVM:** for deserialization-gadget advisories, the call-graph note lists the
  deserialization entry points the app reaches (Java serialization, RMI/JMX, JNDI,
  XMLDecoder, XStream, SnakeYAML, Hessian, Kryo, Jackson default typing) with the path,
  and any `ObjectInputFilter` or `resolveClass` allowlisting. Evidence for the judges;
  gadgets still never settle on Maven.
- **Endpoints:** `SSVC_<NAME>_HEADERS` sends extra request headers (JSON object).

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
