"""The deployed JVM classpath, read from the released artifact (jv1).

JVM apps don't commit lockfiles (none of 22 surveyed self-hosted apps did), and Gradle
builds are code, so the repo alone can't say which versions ship. The release can: a
distribution tarball or zip, a container image's layers, a fat jar or a war carries the
exact jars that run. That is also the only honest answer to "is this optional library
present?": Netty switches codecs on when brotli4j is on the classpath, so the classpath
is the feature flag (the cargofeat question, answered by reading what shipped).

Each jar is identified by the `META-INF/maven/<group>/<artifact>/pom.properties` Maven
builds embed. A jar can carry several: the one matching its file name is its own, the
others are libraries shaded into it (their code is on the classpath too, often under a
relocated package). Jars with none (Gradle-built, or stripped) keep their file name and
sha1 for `identify` to resolve later. Jars nested in jars (Spring Boot BOOT-INF/lib,
WEB-INF/lib in wars, jar-in-jar) are read too, two levels deep.

The artifact is untrusted data: archives are read from disk as streams, entries are
size-checked before they are read, and nothing is extracted or executed. Only
`pom.properties` and the jar bytes needed to hash and open nested jars are read.
"""
from __future__ import annotations

import hashlib
import io
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

MAX_JAR = 512 * 2**20          # one jar (or war) read into memory (Conductor standalone: 373 MB)
MAX_NESTED = 192 * 2**20       # a jar inside a jar (Conductor bundles GraalPy: 100+ MB)
MAX_PROPS = 64 * 2**10         # pom.properties
MAX_ENTRIES = 200_000          # entries in one zip
MAX_JARS = 20_000
DEPTH = 2                      # jar -> nested jar -> (no further)
JAR_EXT = (".jar", ".war", ".ear")
_NESTED_DIRS = ("BOOT-INF/lib/", "WEB-INF/lib/", "WEB-INF/lib-provided/", "lib/", "META-INF/lib/")
_COORD = re.compile(r"^[A-Za-z0-9_.\-]{1,200}$")
_PROPS = re.compile(r"^META-INF/maven/([^/]+)/([^/]+)/pom\.properties$")
_POM = re.compile(r"^META-INF/maven/([^/]+)/([^/]+)/pom\.xml$")
MAX_POM = 512 * 2**10
# artifact-1.2.3.jar, artifact-1.2.3-SNAPSHOT.jar, org.group.artifact-1.2.3.jar (Quarkus lib/main)
_FILENAME = re.compile(r"^(?P<a>.+?)-(?P<v>\d[0-9A-Za-z.\-_+]*)\.(?:jar|war|ear)$")


class Rejected(Exception):
    """The artifact can't be read safely (too large, too many entries, not an archive)."""


@dataclass(frozen=True)
class Coord:
    group: str
    artifact: str
    version: str

    @property
    def name(self) -> str:                       # OSV's Maven package name
        return f"{self.group}:{self.artifact}"

    def __str__(self) -> str:
        return f"{self.group}:{self.artifact}:{self.version}"


@dataclass
class Jar:
    where: str                                   # archive path, `!` separates nesting levels
    sha1: str
    own: Coord | None = None                     # the jar's own coordinates
    shaded: list[Coord] = field(default_factory=list)
    guess: tuple[str, str] | None = None         # (artifact, version) from the file name
    verified: bool = True                        # False: named after a Central artifact whose sha1 differs
    packages: set[str] = field(default_factory=set)            # Java packages its classes are in
    hints: list[str] = field(default_factory=list)             # group guesses from MANIFEST.MF (identify)
    poms: dict[str, list[str]] = field(default_factory=dict)   # "g:a" -> declared runtime deps "g:a"

    @property
    def filename(self) -> str:
        return self.where.rsplit("!", 1)[-1].rsplit("/", 1)[-1]


@dataclass
class Classpath:
    source: str
    jars: list[Jar] = field(default_factory=list)
    removed: set[str] = field(default_factory=set)   # whited-out paths (image layers)

    def coords(self) -> dict[Coord, list[str]]:
        """Every Maven coordinate present -> where (own jars and shaded copies)."""
        out: dict[Coord, list[str]] = {}
        for j in self.jars:
            if j.own:
                out.setdefault(j.own, []).append(j.where)
            for c in j.shaded:
                out.setdefault(c, []).append(f"{j.where} (shaded)")
        return out

    def unidentified(self) -> list[Jar]:
        return [j for j in self.jars if j.own is None]


def _props(data: bytes) -> dict[str, str]:
    out = {}
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")) and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _pom_deps(data: bytes, group: str = "") -> list[str]:
    """A pom.xml (a jar's embedded one, or Central's): the "g:a" it declares for runtime
    (compile/runtime scope, not optional). `${project.groupId}`-style groups resolve to
    `group` (the artifact's own), others are skipped. Untrusted XML: no DTDs or entities are
    accepted, so nothing expands."""
    import xml.etree.ElementTree as ET
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        return []
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return []
    ns = root.tag[:root.tag.index("}") + 1] if root.tag.startswith("{") else ""
    out = []
    deps = root.find(f"{ns}dependencies")
    for d in (deps if deps is not None else ()):
        t = {k: (d.findtext(f"{ns}{k}") or "").strip() for k in ("groupId", "artifactId", "scope", "optional")}
        if t["scope"] in ("test", "provided", "system", "import") or t["optional"] == "true":
            continue
        g, a = t["groupId"], t["artifactId"]
        if group and g in ("${project.groupId}", "${groupId}", "${pom.groupId}", "${project.parent.groupId}"):
            g = group
        if "${" not in g + a and _coord(g, a, "0") and f"{g}:{a}" not in out:
            out.append(f"{g}:{a}")
    return out


def _manifest_hints(data: bytes) -> list[str]:
    """Group guesses a Gradle-built jar (no pom.properties) carries in its manifest: an OSGi
    Bundle-SymbolicName (`io.projectreactor.reactor-core`, `com.github.ben-manes.caffeine`)
    and Gradle's Implementation-Title `group#artifact;version` (micrometer). Guesses only:
    `identify` accepts one only on a Central sha1 match."""
    text = data.decode("utf-8", "replace").replace("\r\n ", "").replace("\n ", "")
    out = []
    for line in text.splitlines():
        k, _, v = line.partition(":")
        v = v.strip().split(";")[0]
        if k == "Implementation-Title" and "#" in v:
            out.append(v.split("#", 1)[0])
        elif k == "Bundle-SymbolicName" and v:
            parts = v.split(".")
            out += [".".join(parts[:i]) for i in range(len(parts), 1, -1)]
    return [g for g in dict.fromkeys(out) if _COORD.match(g)]


def _coord(group: str, artifact: str, version: str) -> Coord | None:
    if all(_COORD.match(x or "") for x in (group, artifact, version)):
        return Coord(group, artifact, version)
    return None


def _guess(filename: str) -> tuple[str, str] | None:
    m = _FILENAME.match(filename)
    return (m["a"], m["v"]) if m else None


def _read_jar(data: bytes, where: str, depth: int, out: list[Jar]) -> None:
    if len(out) >= MAX_JARS:
        raise Rejected("too many jars")
    jar = Jar(where=where, sha1=hashlib.sha1(data).hexdigest())
    out.append(jar)
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError):
        return                                   # not a zip: kept, unidentified
    infos = z.infolist()
    if len(infos) > MAX_ENTRIES:
        raise Rejected(f"{where}: {len(infos)} entries")
    found: list[Coord] = []
    nested = []
    for zi in infos:
        n = zi.filename
        if n == "META-INF/MANIFEST.MF" and zi.file_size <= MAX_PROPS:
            jar.hints = _manifest_hints(z.read(zi))
        elif n.endswith(".class") and not n.startswith("META-INF/") and "/" in n:
            jar.packages.add(n.rsplit("/", 1)[0].replace("/", "."))
        elif (m := _POM.match(n)) and zi.file_size <= MAX_POM:
            if deps := _pom_deps(z.read(zi)):
                jar.poms[f"{m[1]}:{m[2]}"] = deps
        if (m := _PROPS.match(n)) and zi.file_size <= MAX_PROPS:
            p = _props(z.read(zi))
            c = _coord(p.get("groupId", m[1]), p.get("artifactId", m[2]), p.get("version", ""))
            if c and c not in found:
                found.append(c)
        elif depth < DEPTH and n.endswith(JAR_EXT) and n.startswith(_NESTED_DIRS) and not zi.is_dir():
            nested.append(zi)
    jar.guess = _guess(jar.filename)
    if found:
        # its own: the artifact the file name names; else the only one; the rest are shaded
        name = jar.filename
        own = [c for c in found if name.startswith(f"{c.artifact}-{c.version}")
               or name.startswith(f"{c.group}.{c.artifact}-{c.version}")]
        if not own and len(found) == 1:
            own = found
        jar.own = own[0] if own else None
        jar.shaded = [c for c in found if c != jar.own]
    for zi in nested:
        if zi.file_size > MAX_NESTED:
            raise Rejected(f"{where}!{zi.filename}: nested jar too large")
        _read_jar(z.read(zi), f"{where}!{zi.filename}", depth + 1, out)


def _whiteout(name: str) -> str | None:
    """An OCI whiteout's target: `.wh.x` removes x; `.wh..wh..opq` empties its directory."""
    d, _, f = name.rpartition("/")
    if f == ".wh..wh..opq":
        return d + "/"
    if f.startswith(".wh."):
        return (d + "/" if d else "") + f[4:]
    return None


def _clean(name: str) -> str:
    while name.startswith(("./", "/")):
        name = name[2:] if name.startswith("./") else name[1:]
    return name


def _read_tar(path: Path, prefix: str, cp: Classpath) -> None:
    try:
        tf = tarfile.open(path, mode="r|*")      # a stream: one pass, no random access
    except tarfile.TarError as e:
        raise Rejected(f"{path.name}: {e}") from e
    with tf:
        for ti in tf:
            name = _clean(ti.name)
            if (w := _whiteout(name)) is not None:
                cp.removed.add(w)
                continue
            if not ti.isfile() or not name.endswith(JAR_EXT):
                continue
            if ti.size > MAX_JAR:
                raise Rejected(f"{name}: {ti.size} bytes")
            f = tf.extractfile(ti)
            if f is not None:
                _read_jar(f.read(MAX_JAR + 1), f"{prefix}{name}", 0, cp.jars)


def scan(*paths: Path) -> Classpath:
    """Read one artifact, or an image's layers in order (later whiteouts remove earlier
    jars): .tar/.tar.gz/.tgz archives, .zip distributions, or a bare .jar/.war/.ear."""
    cp = Classpath(source=", ".join(p.name for p in paths))
    for i, p in enumerate(paths):
        prefix = f"layer{i}:" if len(paths) > 1 else ""
        before = len(cp.jars)
        if p.suffix in JAR_EXT:
            if p.stat().st_size > MAX_JAR:
                raise Rejected(f"{p.name}: too large")
            _read_jar(p.read_bytes(), f"{prefix}{p.name}", 0, cp.jars)
        elif p.suffix == ".zip":
            with zipfile.ZipFile(p) as z:
                infos = z.infolist()
                if len(infos) > MAX_ENTRIES:
                    raise Rejected(f"{p.name}: {len(infos)} entries")
                for zi in infos:
                    if zi.filename.endswith(JAR_EXT) and not zi.is_dir():
                        if zi.file_size > MAX_JAR:
                            raise Rejected(f"{zi.filename}: too large")
                        _read_jar(z.read(zi), f"{prefix}{zi.filename}", 0, cp.jars)
        else:
            _read_tar(p, prefix, cp)
        if len(paths) > 1 and cp.removed:
            # a whiteout in this layer hides the path (and anything under it) from earlier layers
            def hidden(where: str) -> bool:
                top = where.split("!", 1)[0].split(":", 1)[1]
                return any(top == r or top.startswith(r.rstrip("/") + "/") for r in cp.removed)
            cp.jars = [j for j in cp.jars[:before] if not hidden(j.where)] + cp.jars[before:]
            cp.removed.clear()
    return cp


def _splits(filename: str) -> list[tuple[str, str]]:
    """Every (name, version) a file name allows: `x-4.3-2.5.0-alpha.jar` is x 4.3-2.5.0-alpha
    or x-4.3 2.5.0-alpha."""
    stem = re.sub(r"\.(?:jar|war|ear)$", "", filename)
    out = []
    for m in re.finditer(r"-(?=\d)", stem):
        name, version = stem[:m.start()], stem[m.end():]
        if name and _COORD.match(version) and _coord("g", name, version):
            out.append((name, version))
    return out


def _content_groups(j: Jar) -> list[str]:
    """Group guesses from what a jar holds: its manifest hints, then its packages' 2-4
    segment prefixes, most common first (`org.springframework.core.io` -> org.springframework)."""
    from collections import Counter
    pre = Counter(".".join(p.split(".")[:n]) for p in j.packages for n in (2, 3, 4) if p.count(".") >= n - 1)
    return list(dict.fromkeys(j.hints + [g for g, _ in pre.most_common(8)]))


def _candidates(guess: tuple[str, str], groups, hinted=()) -> list[Coord]:
    name, version = guess
    out = []
    if "." in name:                              # Quarkus lib/main: <group>.<artifact>-<version>.jar
        parts = name.split(".")
        for i in range(len(parts) - 1, 0, -1):
            if c := _coord(".".join(parts[:i]), ".".join(parts[i:]), version):
                out.append(c)
        return out
    # a bare artifact name: the jar's own group guesses, then Central's search (which still
    # knows older versions); every candidate is checked by sha1, so extra guesses cost only lookups
    out = [c for g in hinted if (c := _coord(g, name, version))]
    out += [c for g in groups(name, version) if (c := _coord(g, name, version)) and c not in out]
    return out


IDENT_V = "2"          # 2: group guesses from manifests and packages (Central's search misses recent versions)


def identify(cp: Classpath, *, sha1_of=None, groups=None, cache: Path | None = None) -> int:
    """Give unidentified jars coordinates, accepting a candidate only when Maven Central's
    published sha1 for it equals the shipped jar's sha1 (so a name match alone never
    identifies a jar). Only artifact names and versions are sent. Returns how many were
    identified; the rest stay unidentified (renamed, rebuilt or not on Central)."""
    from . import pkgsrc
    sha1_of = sha1_of or pkgsrc.maven_jar_sha1
    groups = groups or pkgsrc.maven_groups
    cache = cache if cache is not None else pkgsrc.cache_root() / "maven-ident"
    n = 0
    for j in cp.unidentified():
        if not j.guess:
            continue
        hit = cache / f"{j.sha1}.{IDENT_V}.txt"           # a "none" from an older method is retried
        if hit.is_file():
            c = hit.read_text().split()
            if len(c) == 2 and (cc := _coord(*c[0].split(":"))) and len(c[0].split(":")) == 3:
                j.own, j.verified, n = cc, c[1] == "verified", n + 1
            continue
        found, named = None, None
        hinted = _content_groups(j)
        try:
            for c in (c for g in _splits(j.filename) for c in _candidates(g, groups, hinted)):
                got = sha1_of(c.group, c.artifact, c.version)
                if got == j.sha1:
                    found = c
                    break
                named = named or (c if got else None)
        except pkgsrc.Rejected:
            continue                       # Central unreachable or throttled: unknown, so nothing cached
        # a jar named after a Central artifact but rebuilt (Keycloak's h2): kept, flagged
        # unverified, so its advisories still surface (a missed jar is the costly error)
        cache.mkdir(parents=True, exist_ok=True)
        if found or named:
            j.own, j.verified, n = found or named, bool(found), n + 1
            hit.write_text(f"{j.own} {'verified' if found else 'unverified'}\n")
        else:
            hit.write_text("none\n")
    return n


def deployed(cp: Classpath, include: list[str] | tuple = (), exclude: list[str] | tuple = (),
             first_party: list[str] | tuple = ()) -> dict[Coord, Jar]:
    """The third-party coordinates that run: jars under `include` globs (default: all) and
    not under `exclude` (a release's CLI client, docs, examples), matched on the archive
    path; groups starting with a `first_party` prefix are the app itself, not dependencies.
    Shaded copies count. Coord -> the first jar it was found in."""
    from fnmatch import fnmatch
    out: dict[Coord, Jar] = {}
    for j in cp.jars:
        top = j.where.split("!", 1)[0]
        top = top.split(":", 1)[1] if re.match(r"^layer\d+:", top) else top
        if include and not any(fnmatch(top, g) for g in include):
            continue
        if any(fnmatch(top, g) for g in exclude):
            continue
        for c in ([j.own] if j.own else []) + j.shaded:
            if not any(c.group == p or c.group.startswith(p + ".") for p in first_party):
                out.setdefault(c, j)
    return out


# --- the classpath index judges read, keyed by the checkout ----------------------------

_REGISTRY: dict[str, dict] = {}
INDEX_V = "6"


def register(repo: str | Path, artifact: dict) -> None:
    """Say which release artifact a checkout deploys, so judges (which get only the repo
    path) can look up the classpath. Also written to disk for other processes."""
    import json
    key = str(Path(repo).expanduser().resolve())
    _REGISTRY[key] = artifact
    d = _cache() / "registry"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{hashlib.sha256(key.encode()).hexdigest()[:20]}.json").write_text(json.dumps({"repo": key, **artifact}))


def _cache() -> Path:
    import os
    return Path(os.environ.get("SSVC_JUDGE_CACHE", "~/.cache/ssvc-triage/judge")).expanduser() / "jvm"


def artifact_for(repo: str | Path) -> dict | None:
    import json
    key = str(Path(repo).expanduser().resolve())
    if key in _REGISTRY:
        return _REGISTRY[key]
    f = _cache() / "registry" / f"{hashlib.sha256(key.encode()).hexdigest()[:20]}.json"
    if f.is_file():
        a = json.loads(f.read_text())
        a.pop("repo", None)
        return _REGISTRY.setdefault(key, a)
    return None


def index(repo: str | Path) -> dict | None:
    """The deployed classpath of a registered checkout: {"g:a": {"version", "jar", "verified",
    "packages", "deps"}}. Built once per artifact (keyed on paths, sizes and mtimes)."""
    import json
    a = artifact_for(repo)
    if a is None:
        return None
    st = [(p, Path(p).stat().st_size, Path(p).stat().st_mtime_ns) for p in a["paths"]]
    key = hashlib.sha256(json.dumps([INDEX_V, st, a.get("include"), a.get("exclude"), a.get("first_party")],
                                    sort_keys=True).encode()).hexdigest()[:24]
    f = _cache() / f"index-{key}.json"
    if f.is_file():
        return json.loads(f.read_text())
    cp = scan(*[Path(p) for p in a["paths"]])
    if a.get("identify", True):
        identify(cp)
    out = {}
    online = a.get("identify", True)
    for c, j in deployed(cp, a.get("include") or (), a.get("exclude") or (), a.get("first_party") or ()).items():
        deps = j.poms.get(c.name)
        if deps is None and online:
            deps = _central_deps(c)                  # Gradle-built: no pom.xml in the jar
        out.setdefault(c.name, {"version": c.version, "jar": j.where, "verified": j.verified and j.own == c,
                                "sha1": j.sha1 if j.own == c and j.verified else "",
                                "shaded_in": None if j.own == c else (str(j.own) if j.own else j.filename),
                                "packages": sorted(j.packages if j.own == c else _shaded_packages(j, c)),
                                "deps": deps or []})
    # the app's own jars (first_party groups) declare its direct dependencies
    fp = tuple(a.get("first_party") or ())
    app = sorted({d for j in cp.jars for c in ([j.own] if j.own else []) + j.shaded
                  if any(c.group == p or c.group.startswith(p + ".") for p in fp) for d in j.poms.get(c.name, [])})
    out = {"__app__": {"deps": app, "known": bool(fp)}, **out}
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(out))
    return out


def _central_deps(c: Coord) -> list[str]:
    """The runtime dependencies Central's published pom declares for `c` ([] when it has none,
    or Central can't be reached: the graph then just lacks those edges, as before)."""
    from . import pkgsrc
    try:
        pom = pkgsrc.maven_pom(c.group, c.artifact, c.version)
    except pkgsrc.Rejected:
        return []
    return _pom_deps(pom, c.group) if pom else []


def _shaded_packages(j: Jar, c: Coord) -> set[str]:
    """A library shaded into another jar (an uber/shadow jar holds 100+): its packages are
    the jar's packages under its own group (io.netty -> io.netty.*), else under the group's
    first two segments; never the whole jar's, which would credit every import to it."""
    for pre in (c.group, ".".join(c.group.split(".")[:2])):
        got = {p for p in j.packages if p == pre or p.startswith(pre + ".")}
        if got:
            return got
    return set()


def packages_of(repo: str | Path, name: str) -> list[str]:
    ix = index(repo) or {}
    return (ix.get(name) or {}).get("packages") or []
