"""jvmcallers: who calls the advisory's code, from the release's bytecode (jv2's one miss)."""
import io
import struct
import tarfile
import zipfile

from doublestrain import jvmcallers, jvmjars


def _class(name, sup="java/lang/Object", methods=(), ifaces=()):
    """A minimal class file: `methods` = [(name, [(owner, callee, kind)])], kind "static"/"virtual"/"interface"."""
    cp, idx = [], {}
    def add(key, raw):
        if key not in idx:
            cp.append(raw); idx[key] = len(cp)
        return idx[key]
    def utf(s):
        b = s.encode(); return add(("u", s), b"\x01" + struct.pack(">H", len(b)) + b)
    def cls(s):
        return add(("c", s), b"\x07" + struct.pack(">H", utf(s)))
    def mref(o, n, iface):
        nt = add(("nt", n), b"\x0c" + struct.pack(">HH", utf(n), utf("()V")))
        return add(("m", o, n, iface), (b"\x0b" if iface else b"\x0a") + struct.pack(">HH", cls(o), nt))
    this, supi = cls(name), cls(sup)
    ifi = [cls(i) for i in ifaces]
    code_name = utf("Code")
    body = []
    for mname, calls in methods:
        code = b""
        for o, n, kind in calls:
            if kind == "interface":
                code += b"\xb9" + struct.pack(">H", mref(o, n, True)) + b"\x01\x00"
            else:
                code += (b"\xb8" if kind == "static" else b"\xb6") + struct.pack(">H", mref(o, n, False))
        code += b"\xb1"                                              # return
        attr = struct.pack(">HHI", 2, 2, len(code)) + code + struct.pack(">HH", 0, 0)
        body.append(struct.pack(">HHHH", 1, utf(mname), utf("()V"), 1) + struct.pack(">HI", code_name, len(attr)) + attr)
    head = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, len(cp) + 1) + b"".join(cp)
    return (head + struct.pack(">HHHH", 0x21, this, supi, len(ifi)) + b"".join(struct.pack(">H", i) for i in ifi)
            + struct.pack(">H", 0) + struct.pack(">H", len(body)) + b"".join(body) + struct.pack(">H", 0))


def _jar(entries):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, data in entries.items():
            z.writestr(n, data)
    return b.getvalue()


def test_parse_class_reads_calls():
    c = _class("a/B", methods=[("run", [("x/Y", "go", "static"), ("x/I", "m", "interface")])])
    this, sup, ifaces, meths = jvmcallers.parse_class(c)
    assert this == "a/B" and sup == "java/lang/Object" and meths["run"] == {("x/Y", "go"), ("x/I", "m")}


def test_chain_through_a_library_the_app_calls(tmp_path, monkeypatch):
    # jv2's miss in miniature: app -> pkix PEMParser.readObject -> pkix CRLHolder.parse (via an
    # interface) -> prov ASN1InputStream.<init>; prov's own reader is never called by the app
    monkeypatch.setenv("SSVC_JUDGE_CACHE", str(tmp_path / "cache"))
    jvmjars._REGISTRY.clear()
    jvmcallers._reverse.cache_clear()
    prov = _jar({"META-INF/maven/org.bc/bcprov/pom.properties": "groupId=org.bc\nartifactId=bcprov\nversion=1.80\n",
                 "org/bc/asn1/ASN1InputStream.class": _class("org/bc/asn1/ASN1InputStream", methods=[("<init>", []), ("readObject", [])]),
                 "org/bc/asn1/Other.class": _class("org/bc/asn1/Other", methods=[("x", [])])})
    pkix = _jar({"META-INF/maven/org.bc/bcpkix/pom.properties": "groupId=org.bc\nartifactId=bcpkix\nversion=1.80\n",
                 "org/bc/pem/Parser.class": _class("org/bc/pem/Parser", ifaces=[]),
                 "org/bc/pem/PEMParser.class": _class("org/bc/pem/PEMParser", methods=[("readObject", [("org/bc/pem/Parser", "parse", "interface")])]),
                 "org/bc/pem/CRLHolder.class": _class("org/bc/pem/CRLHolder", ifaces=["org/bc/pem/Parser"],
                                                      methods=[("parse", [("org/bc/asn1/ASN1InputStream", "<init>", "virtual")])])})
    app = _jar({"BOOT-INF/classes/com/app/Sign.class": _class("com/app/Sign", methods=[("upload", [("org/bc/pem/PEMParser", "readObject", "virtual")])]),
                "BOOT-INF/classes/com/app/Idle.class": _class("com/app/Idle", methods=[("x", [("org/bc/asn1/Other", "x", "static")])]),
                "BOOT-INF/lib/bcprov-1.80.jar": prov, "BOOT-INF/lib/bcpkix-1.80.jar": pkix})
    art = tmp_path / "app.jar"; art.write_bytes(app)
    repo = tmp_path / "repo"; repo.mkdir()
    jvmjars.register(repo, {"paths": [str(art)], "identify": False})
    note = jvmcallers.callers_note(str(repo), "maven", "org.bc:bcprov", "1.80", ["new ASN1InputStream(in, true)"])
    assert "Sign.upload [app] -> PEMParser.readObject [bcpkix] -> CRLHolder.parse [bcpkix] -> ASN1InputStream.<init> [bcprov]" in note
    assert "Idle" not in note and "org.bc:bcpkix" in note
    assert jvmcallers.caller_coords(str(repo), "org.bc:bcprov", ["ASN1InputStream"]) == ["org.bc:bcpkix"]
    # nothing in the app reaches a method only bcprov itself calls
    assert "no method of the app's own classes reaches them" in jvmcallers.callers_note(
        str(repo), "maven", "org.bc:bcprov", "1.80", ["ASN1InputStream.readObject"])


def test_hostile_class_files_are_skipped():
    for junk in (b"", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbe" + b"\x00" * 6 + b"\xff\xff", b"PK\x03\x04garbage"):
        try:
            jvmcallers.parse_class(junk)
            raise AssertionError("parsed junk")
        except jvmcallers._Bad:
            pass
