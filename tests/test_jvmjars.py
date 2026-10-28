"""jvmjars: the deployed JVM classpath, read from the released artifact (jv1)."""
import io
import json
import tarfile
import zipfile

import pytest

from doublestrain import jvmjars
from doublestrain.jvmjars import Coord


def _jar(*poms: tuple[str, str, str], nested: dict[str, bytes] | None = None, extra: dict[str, bytes] | None = None) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        for g, a, v in poms:
            z.writestr(f"META-INF/maven/{g}/{a}/pom.properties", f"#generated\ngroupId={g}\nartifactId={a}\nversion={v}\n")
        for n, data in (nested or {}).items():
            z.writestr(n, data)
        for n, data in (extra or {}).items():
            z.writestr(n, data)
    return b.getvalue()


def _tar(path, files: dict[str, bytes]):
    with tarfile.open(path, "w:gz") as t:
        for n, data in files.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return path


def test_distribution_tarball_own_shaded_and_unidentified(tmp_path):
    netty = _jar(("io.netty", "netty-codec-http", "4.1.100.Final"))
    shaded = _jar(("com.example", "client", "2.0.0"), ("com.google.guava", "guava", "31.1-jre"))
    gradle = _jar()                                       # Gradle-built: no pom.properties
    p = _tar(tmp_path / "app-1.0.tar.gz", {
        "app-1.0/lib/netty-codec-http-4.1.100.Final.jar": netty,
        "app-1.0/lib/client-2.0.0.jar": shaded,
        "app-1.0/lib/okhttp-4.12.0.jar": gradle,
        "app-1.0/conf/app.conf": b"x=1\n",
    })
    cp = jvmjars.scan(p)
    got = cp.coords()
    assert Coord("io.netty", "netty-codec-http", "4.1.100.Final") in got
    assert got[Coord("com.google.guava", "guava", "31.1-jre")] == ["app-1.0/lib/client-2.0.0.jar (shaded)"]
    (u,) = cp.unidentified()
    assert u.guess == ("okhttp", "4.12.0") and len(u.sha1) == 40
    assert Coord("io.netty", "netty-codec-http", "4.1.100.Final").name == "io.netty:netty-codec-http"


def test_fat_jar_and_war_nesting(tmp_path):
    inner = _jar(("org.yaml", "snakeyaml", "1.33"))
    boot = _jar(("com.acme", "service", "3.1.0"), nested={"BOOT-INF/lib/snakeyaml-1.33.jar": inner,
                                                          "BOOT-INF/classes/application.yml": b"a: 1\n"})
    (tmp_path / "service-3.1.0.jar").write_bytes(boot)
    cp = jvmjars.scan(tmp_path / "service-3.1.0.jar")
    assert cp.coords()[Coord("org.yaml", "snakeyaml", "1.33")] == ["service-3.1.0.jar!BOOT-INF/lib/snakeyaml-1.33.jar"]
    war = _jar(nested={"WEB-INF/lib/snakeyaml-1.33.jar": inner})
    z = tmp_path / "dist.zip"
    with zipfile.ZipFile(z, "w") as zz:
        zz.writestr("dist/webapps/ROOT.war", war)
    assert Coord("org.yaml", "snakeyaml", "1.33") in jvmjars.scan(z).coords()


def test_quarkus_names_and_image_whiteouts(tmp_path):
    # Keycloak/Quarkus: lib/main/<group>.<artifact>-<version>.jar
    q = _jar(("org.apache.kafka", "kafka-clients", "3.7.0"), ("com.github.luben", "zstd-jni", "1.5.5-6"))
    old = _jar(("org.bouncycastle", "bcprov-jdk18on", "1.76"))
    l0 = _tar(tmp_path / "l0.tar.gz", {"opt/app/lib/main/org.apache.kafka.kafka-clients-3.7.0.jar": q,
                                       "opt/app/lib/main/org.bouncycastle.bcprov-jdk18on-1.76.jar": old,
                                       "opt/app/plugins/x-1.0.jar": old})
    l1 = _tar(tmp_path / "l1.tar.gz", {"opt/app/lib/main/.wh.org.bouncycastle.bcprov-jdk18on-1.76.jar": b"",
                                       "opt/app/plugins/.wh..wh..opq": b""})
    cp = jvmjars.scan(l0, l1)
    got = cp.coords()
    assert got[Coord("org.apache.kafka", "kafka-clients", "3.7.0")] == ["layer0:opt/app/lib/main/org.apache.kafka.kafka-clients-3.7.0.jar"]
    assert Coord("com.github.luben", "zstd-jni", "1.5.5-6") in got          # shaded into kafka-clients
    assert Coord("org.bouncycastle", "bcprov-jdk18on", "1.76") not in got   # whited out, file and opaque dir


def test_hostile_input_is_rejected_or_ignored(tmp_path, monkeypatch):
    bad = _jar(("../../etc", "x", "1"), extra={"META-INF/maven/g/a/pom.properties": b"groupId=g\nartifactId=a\nversion=1 && rm\n"})
    (tmp_path / "bad.jar").write_bytes(bad)
    assert jvmjars.scan(tmp_path / "bad.jar").coords() == {}               # names that aren't coordinates are dropped
    monkeypatch.setattr(jvmjars, "MAX_JAR", 10)
    with pytest.raises(jvmjars.Rejected):
        jvmjars.scan(_tar(tmp_path / "big.tar.gz", {"lib/a-1.0.jar": bad}))
    (tmp_path / "notzip.jar").write_bytes(b"not a zip")
    monkeypatch.setattr(jvmjars, "MAX_JAR", 2**20)
    (j,) = jvmjars.scan(tmp_path / "notzip.jar").jars
    assert j.own is None and j.guess is None


def test_identify_only_on_a_central_sha1_match(tmp_path):
    otel, bc, fork = _jar(), _jar(extra={"x": b"1"}), _jar(extra={"x": b"2"})
    p = _tar(tmp_path / "a.tar.gz", {"lib/main/io.opentelemetry.opentelemetry-sdk-1.39.0.jar": otel,
                                     "client/lib/bcprov-jdk18on-1.78.1.jar": bc,
                                     "lib/guava-31.1-jre.jar": fork})       # rebuilt: Central's sha1 differs
    cp = jvmjars.scan(p)
    sha = {j.filename: j.sha1 for j in cp.jars}
    central = {("io.opentelemetry", "opentelemetry-sdk", "1.39.0"): sha["io.opentelemetry.opentelemetry-sdk-1.39.0.jar"],
               ("org.bouncycastle", "bcprov-jdk18on", "1.78.1"): sha["bcprov-jdk18on-1.78.1.jar"],
               ("com.google.guava", "guava", "31.1-jre"): "0" * 40}
    asked = []
    def sha1_of(g, a, v):
        asked.append((g, a, v)); return central.get((g, a, v))
    groups = lambda a, v: {"bcprov-jdk18on": ["org.bouncycastle"], "guava": ["com.google.guava"]}.get(a, [])  # noqa: E731
    assert jvmjars.identify(cp, sha1_of=sha1_of, groups=groups, cache=tmp_path / "c") == 3
    got = cp.coords()
    assert Coord("io.opentelemetry", "opentelemetry-sdk", "1.39.0") in got and Coord("org.bouncycastle", "bcprov-jdk18on", "1.78.1") in got
    (g,) = [j for j in cp.jars if j.filename == "guava-31.1-jre.jar"]
    assert g.own == Coord("com.google.guava", "guava", "31.1-jre") and not g.verified   # rebuilt: kept, flagged
    assert not cp.unidentified()
    asked.clear()                                                           # cached: no second lookup
    cp2 = jvmjars.scan(p)
    assert jvmjars.identify(cp2, sha1_of=sha1_of, groups=groups, cache=tmp_path / "c") == 3 and not asked
    assert [j.verified for j in cp2.jars if j.filename == "guava-31.1-jre.jar"] == [False]


def test_deployed_scoping_and_first_party(tmp_path):
    p = _tar(tmp_path / "kc.tar.gz", {
        "kc/lib/lib/main/org.keycloak.keycloak-core-26.1.4.jar": _jar(("org.keycloak", "keycloak-core", "26.1.4")),
        "kc/lib/lib/main/io.netty.netty-codec-http-4.1.118.Final.jar": _jar(("io.netty", "netty-codec-http", "4.1.118.Final")),
        "kc/bin/client/lib/bcprov-jdk18on-1.78.1.jar": _jar(("org.bouncycastle", "bcprov-jdk18on", "1.78.1")),
    })
    cp = jvmjars.scan(p)
    got = jvmjars.deployed(cp, exclude=["*/bin/client/*"], first_party=["org.keycloak"])
    assert set(got) == {Coord("io.netty", "netty-codec-http", "4.1.118.Final")}
    assert set(jvmjars.deployed(cp, include=["kc/bin/*"])) == {Coord("org.bouncycastle", "bcprov-jdk18on", "1.78.1")}
    from doublestrain import osv
    deps = osv.parse_artifact({"paths": [str(p)], "exclude": ["*/bin/client/*"], "first_party": ["org.keycloak"],
                               "identify": False})
    assert [(d.name, d.version, d.ecosystem, d.dev) for d in deps] == [("io.netty:netty-codec-http", "4.1.118.Final", "Maven", False)]


def test_index_packages_and_pom_edges(tmp_path, monkeypatch):
    monkeypatch.setenv("SSVC_JUDGE_CACHE", str(tmp_path / "cache"))
    jvmjars._REGISTRY.clear()
    pom = (b'<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies>'
           b'<dependency><groupId>io.netty</groupId><artifactId>netty-codec</artifactId></dependency>'
           b'<dependency><groupId>com.aayushatharva.brotli4j</groupId><artifactId>brotli4j</artifactId><optional>true</optional></dependency>'
           b'<dependency><groupId>junit</groupId><artifactId>junit</artifactId><scope>test</scope></dependency>'
           b'</dependencies></project>')
    http = _jar(("io.netty", "netty-codec-http", "4.1.118.Final"),
                extra={"META-INF/maven/io.netty/netty-codec-http/pom.xml": pom,
                       "io/netty/handler/codec/http/HttpObjectDecoder.class": b"\xca\xfe",
                       "io/netty/handler/codec/http/websocketx/WebSocket08FrameDecoder.class": b"\xca\xfe"})
    evil = _jar(("x", "evil", "1"), extra={"META-INF/maven/x/evil/pom.xml":
                b'<!DOCTYPE p [<!ENTITY a "aaaa">]><project><dependencies><dependency><groupId>&a;</groupId>'
                b'<artifactId>b</artifactId></dependency></dependencies></project>'})
    art = _tar(tmp_path / "a.tar.gz", {"lib/netty-codec-http-4.1.118.Final.jar": http, "lib/evil-1.jar": evil})
    repo = tmp_path / "repo"; repo.mkdir()
    jvmjars.register(repo, {"paths": [str(art)], "identify": False})
    jvmjars._REGISTRY.clear()                                   # another process: read from disk
    ix = jvmjars.index(repo)
    h = ix["io.netty:netty-codec-http"]
    assert h["version"] == "4.1.118.Final" and h["verified"] and h["deps"] == ["io.netty:netty-codec"]
    assert h["packages"] == ["io.netty.handler.codec.http", "io.netty.handler.codec.http.websocketx"]
    assert ix["x:evil"]["deps"] == []                           # DTD/entities: refused, nothing expands
    assert jvmjars.index(tmp_path / "other") is None


def test_judge_view_imports_chains_and_reflection(tmp_path, monkeypatch):
    from doublestrain.judges import depgraph
    from doublestrain.judges.usage import usage_summary
    monkeypatch.setenv("SSVC_JUDGE_CACHE", str(tmp_path / "cache"))
    jvmjars._REGISTRY.clear()
    def pom(*deps):
        body = "".join(f"<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId></dependency>" for g, a in deps)
        return f"<project><dependencies>{body}</dependencies></project>".encode()
    app = _jar(("org.acme", "acme-server", "1.0"), extra={"META-INF/maven/org.acme/acme-server/pom.xml": pom(("io.vertx", "vertx-web"))})
    web = _jar(("io.vertx", "vertx-web", "4.5.11"), extra={"META-INF/maven/io.vertx/vertx-web/pom.xml": pom(("io.netty", "netty-codec-http")),
                                                          "io/vertx/ext/web/Router.class": b"\xca\xfe"})
    http = _jar(("io.netty", "netty-codec-http", "4.1.118.Final"), extra={"io/netty/handler/codec/http/HttpObjectDecoder.class": b"\xca\xfe"})
    art = _tar(tmp_path / "a.tar.gz", {"lib/acme-server-1.0.jar": app, "lib/vertx-web-4.5.11.jar": web,
                                       "lib/netty-codec-http-4.1.118.Final.jar": http})
    repo = tmp_path / "repo"
    (repo / "src/main/java/org/acme").mkdir(parents=True)
    (repo / "src/main/java/org/acme/Server.java").write_text(
        "package org.acme;\nimport io.vertx.ext.web.Router;\nclass Server { Object p = Class.forName(name); }\n")
    jvmjars.register(repo, {"paths": [str(art)], "first_party": ["org.acme"], "identify": False})
    g = depgraph.load(repo, "maven")
    assert g.direct == {"io.vertx:vertx-web"} and "org.acme:acme-server" not in g.nodes
    assert depgraph.chains(g, "io.netty:netty-codec-http") == [["io.vertx:vertx-web", "io.netty:netty-codec-http"]]
    u = usage_summary(str(repo), "maven", "io.netty:netty-codec-http", ["HttpObjectDecoder"], version="4.1.118.Final")
    assert not u.import_sites and u.chains and u.entry_sites == ["src/main/java/org/acme/Server.java:2: import io.vertx.ext.web.Router;"]
    assert u.dynamic_sites                                    # Class.forName(name): not closed-world
    u2 = usage_summary(str(repo), "maven", "io.vertx:vertx-web", [], version="4.5.11")
    assert u2.import_sites == ["src/main/java/org/acme/Server.java:2: import io.vertx.ext.web.Router;"]


def test_maven_sources_only_for_the_published_jar(tmp_path, monkeypatch):
    import hashlib
    from doublestrain import pkgsrc
    monkeypatch.setenv("SSVC_PKGSRC_CACHE", str(tmp_path / "pk"))
    shipped = _jar(("io.netty", "netty-codec-http", "4.1.118.Final"))
    jar_sha = hashlib.sha1(shipped).hexdigest()
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("io/netty/handler/codec/http/HttpObjectDecoder.java", "class HttpObjectDecoder {}\n")
        z.writestr("META-INF/MANIFEST.MF", "x")
        z.writestr("build.sh", "rm -rf /\n")
    sources = b.getvalue()
    base = "https://repo1.maven.org/maven2/io/netty/netty-codec-http/4.1.118.Final/netty-codec-http-4.1.118.Final"
    served = {base + ".jar.sha1": jar_sha.encode(), base + "-sources.jar.sha1": hashlib.sha1(sources).hexdigest().encode(),
              base + "-sources.jar": sources}
    def get(url, cap, timeout=60.0):
        if url not in served:
            raise pkgsrc.Rejected(f"404 {url}")
        return served[url]
    monkeypatch.setattr(pkgsrc, "_get", get)
    d = pkgsrc.fetch_maven("io.netty:netty-codec-http", "4.1.118.Final", f"sha1:{jar_sha}")
    files = sorted(p.relative_to(d).as_posix() for p in d.rglob("*") if p.is_file())
    assert files == ["io/netty/handler/codec/http/HttpObjectDecoder.java"]
    with pytest.raises(pkgsrc.Rejected, match="no verified jar"):            # rebuilt or unidentified: no source
        pkgsrc.fetch_maven("io.netty:netty-codec-http", "4.1.118.Final", "")
    sh = pkgsrc.fetch_maven("io.netty:netty-codec-http", "4.1.118.Final", "shaded")   # bundled copy: published source
    assert json.loads(sh.with_name(sh.name + ".json").read_text())["verified"]["shaded"] is True
    with pytest.raises(pkgsrc.Rejected, match="not Central's published jar"):
        pkgsrc.fetch_maven("io.netty:netty-codec-http", "4.1.118.Final", "sha1:" + "1" * 40)
    with pytest.raises(pkgsrc.Rejected, match="invalid"):
        pkgsrc.fetch_maven("../x:y", "1", f"sha1:{jar_sha}")
    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../../escape.java", "x")
    with pytest.raises(pkgsrc.Rejected, match="hostile"):
        pkgsrc._extract_zip(evil.getvalue(), tmp_path / "out", pkgsrc.JVM_EXT)


def test_maven_judges_are_not_skipped(tmp_path, monkeypatch):
    # jv1's first split run answered nothing: split's ecosystem allowlist lacked maven
    from doublestrain.judges import split, claude_code
    from doublestrain.judges.base import ReachQuery
    assert "maven" in split.ECOSYSTEMS and "maven" in dict(split._SALT)
    seen = []
    monkeypatch.setattr(claude_code.pkgsrc_mod, "for_query", lambda *a, **k: (seen.append(k["ecosystem"]), ([], []))[1])
    j = claude_code.ClaudeCodeJudge(pkgsrc=True)
    j._sources(ReachQuery(str(tmp_path), "maven", "io.netty:netty-codec-http", "CVE-1", version="4.1.118.Final"))
    assert seen == ["maven"]


def test_trace_steps_may_drop_the_maven_group(tmp_path):
    from doublestrain.judges.claude_code import check_trace
    d = tmp_path / "src"
    (d / "com/x").mkdir(parents=True)
    (d / "com/x/Mapper.java").write_text("class Mapper {\n  public Object readValue(String content) {\n")
    src = [("com.fasterxml.jackson.core:jackson-databind@2.17.1", d)]
    step = {"line": 2, "quote": "public Object readValue(String content) {"}
    for path in ("jackson-databind@2.17.1/com/x/Mapper.java", "com.fasterxml.jackson.core:jackson-databind@2.17.1/com/x/Mapper.java"):
        ok, bad = check_trace([{**step, "path": path}], src, "com.fasterxml.jackson.core:jackson-databind")
        assert ok == ["com.fasterxml.jackson.core:jackson-databind@2.17.1/com/x/Mapper.java:2"] and not bad
    ok, bad = check_trace([{**step, "path": "jackson-core@2.17.1/com/x/Mapper.java"}], src, "x")
    assert not ok and bad


def test_identify_gradle_jars_from_manifest_and_packages(tmp_path):
    # Central's search API has no recent versions (jv2: Halo's Spring/reactor/caffeine jars);
    # a Gradle-built jar's manifest and packages say its group
    reactor = _jar(extra={"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\nBundle-SymbolicName: io.projectreactor.reactor-core\r\n",
                          "reactor/core/publisher/Flux.class": b"\xca\xfe"})
    spring = _jar(extra={"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\nAutomatic-Module-Name: spring.core\r\n",
                         "org/springframework/core/io/Resource.class": b"\xca\xfe",
                         "org/springframework/util/Assert.class": b"\xca\xfe"})
    mm = _jar(extra={"META-INF/MANIFEST.MF": b"Implementation-Title: io.micrometer#micrometer-core;1.15.2\r\n"})
    p = _tar(tmp_path / "a.tar.gz", {"lib/reactor-core-3.7.8.jar": reactor, "lib/spring-core-6.2.9.jar": spring,
                                     "lib/micrometer-core-1.15.2.jar": mm})
    cp = jvmjars.scan(p)
    sha = {j.filename: j.sha1 for j in cp.jars}
    central = {("io.projectreactor", "reactor-core", "3.7.8"): sha["reactor-core-3.7.8.jar"],
               ("org.springframework", "spring-core", "6.2.9"): sha["spring-core-6.2.9.jar"],
               ("io.micrometer", "micrometer-core", "1.15.2"): sha["micrometer-core-1.15.2.jar"]}
    assert jvmjars.identify(cp, sha1_of=lambda g, a, v: central.get((g, a, v)), groups=lambda a, v: [],
                            cache=tmp_path / "c") == 3
    assert {str(j.own) for j in cp.jars} == {"io.projectreactor:reactor-core:3.7.8", "org.springframework:spring-core:6.2.9",
                                             "io.micrometer:micrometer-core:1.15.2"}
    assert all(j.verified for j in cp.jars)


def test_identify_does_not_cache_a_failed_lookup(tmp_path):
    from doublestrain import pkgsrc
    p = _tar(tmp_path / "a.tar.gz", {"lib/guava-31.1-jre.jar": _jar(extra={"com/google/common/base/A.class": b"\xca\xfe"})})
    cp = jvmjars.scan(p)
    def throttled(g, a, v):
        raise pkgsrc.Rejected("fetch failed: HTTP Error 429: Too Many Requests")
    assert jvmjars.identify(cp, sha1_of=throttled, groups=lambda a, v: [], cache=tmp_path / "c") == 0
    assert not list((tmp_path / "c").glob("*")) if (tmp_path / "c").exists() else True
    sha = cp.jars[0].sha1
    assert jvmjars.identify(cp, sha1_of=lambda g, a, v: sha if g == "com.google.common" or g == "com.google.guava" else None,
                            groups=lambda a, v: ["com.google.guava"], cache=tmp_path / "c") == 1


def test_gradle_jars_get_their_edges_from_centrals_pom(tmp_path, monkeypatch):
    # jv2 miss: bcpkix (Gradle-built, no pom.xml in the jar) had no edge to bcprov, so the
    # judges never got bcpkix's source; Central's published pom has the edge
    from doublestrain import pkgsrc
    from doublestrain.judges import depgraph
    monkeypatch.setenv("SSVC_JUDGE_CACHE", str(tmp_path / "cache"))
    jvmjars._REGISTRY.clear()
    poms = {("org.bouncycastle", "bcpkix-jdk18on", "1.80"): b'<project><dependencies><dependency><groupId>${project.groupId}</groupId>'
                                                           b'<artifactId>bcutil-jdk18on</artifactId></dependency></dependencies></project>',
            ("org.bouncycastle", "bcutil-jdk18on", "1.80"): b'<project><dependencies><dependency><groupId>org.bouncycastle</groupId>'
                                                           b'<artifactId>bcprov-jdk18on</artifactId></dependency></dependencies></project>'}
    monkeypatch.setattr(pkgsrc, "maven_pom", lambda g, a, v: poms.get((g, a, v)))
    jars = {f"lib/{a}-1.80.jar": _jar(("org.bouncycastle", a, "1.80")) for a in ("bcpkix-jdk18on", "bcutil-jdk18on", "bcprov-jdk18on")}
    art = _tar(tmp_path / "a.tar.gz", jars)
    repo = tmp_path / "repo"; repo.mkdir()
    jvmjars.register(repo, {"paths": [str(art)]})
    ix = jvmjars.index(repo)
    assert ix["org.bouncycastle:bcpkix-jdk18on"]["deps"] == ["org.bouncycastle:bcutil-jdk18on"]
    g = depgraph.load(repo, "maven")
    assert g.edges[""] == ("org.bouncycastle:bcpkix-jdk18on",)          # a Gradle app: roots are what nothing needs
    assert depgraph.chains(g, "org.bouncycastle:bcprov-jdk18on") == [
        ["org.bouncycastle:bcpkix-jdk18on", "org.bouncycastle:bcutil-jdk18on", "org.bouncycastle:bcprov-jdk18on"]]
