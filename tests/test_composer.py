"""Composer projects: composer.lock + composer.json -> deps, dev split, chains (replace /
provide), PHP import sites, the not_reachable hold, and verified source from a pinned git
commit. Offline: the git test fetches from a local bare repository it builds itself."""
import json
import subprocess

import pytest

from doublestrain import composer, names, osv, pkgsrc
from doublestrain.judges import depgraph
from doublestrain.judges.base import Verdict
from doublestrain.judges.usage import guard_not_reachable, usage_summary

GH = "https://github.com/{}.git"


def _p(name, version, require=(), ns=(), replace=(), path=False, ref="a" * 40):
    m = {"name": name, "version": version, "require": {r: "^1" for r in require},
         "autoload": {"psr-4": {f"{n}\\": "src/" for n in ns}}}
    if replace:
        m["replace"] = {r: "self.version" for r in replace}
    if path:
        m["dist"] = {"type": "path", "url": "./packages/x"}
    else:
        m["source"] = {"type": "git", "url": GH.format(name), "reference": ref}
        m["dist"] = {"type": "zip", "url": f"https://api.github.com/repos/{name}/zipball/{ref}", "shasum": ""}
    return m


@pytest.fixture
def app(tmp_path):
    (tmp_path / "composer.json").write_text(json.dumps({
        "require": {"php": ">=8.1", "ext-json": "*", "Laravel/Framework": "^10", "acme/local": "*"},
        "require-dev": {"phpunit/phpunit": "^10"}}))
    (tmp_path / "composer.lock").write_text(json.dumps({
        "packages": [
            _p("laravel/framework", "v10.48.4", ["php", "symfony/http-kernel", "monolog/monolog"],
               ["Illuminate"], replace=["illuminate/support"]),
            _p("symfony/http-kernel", "v6.4.5", ["symfony/http-foundation", "psr/log"], ["Symfony\\Component\\HttpKernel"]),
            _p("symfony/http-foundation", "v6.4.4", [], ["Symfony\\Component\\HttpFoundation"]),
            _p("monolog/monolog", "3.5.0", ["psr/log"], ["Monolog"]),
            _p("psr/log", "3.0.0", [], ["Psr\\Log"]),
            _p("spatie/thing", "1.0.0", ["illuminate/support"], ["Spatie\\Thing"]),
            _p("acme/local", "dev-main", ["psr/log"], ["Acme"], path=True),     # the app's own package
        ],
        "packages-dev": [_p("phpunit/phpunit", "10.5.0", ["psr/log"], ["PHPUnit"])],
    }))
    (tmp_path / "app").mkdir()
    (tmp_path / "app/Kernel.php").write_text(
        "<?php\nnamespace App;\nuse Symfony\\Component\\HttpFoundation\\Request;\n"
        "// use Monolog\\Logger;\n$h = new \\Monolog\\Handler\\StreamHandler('x');\n"
        "$cls = 'Symfony\\\\Component\\\\HttpKernel\\\\Kernel';\n")
    (tmp_path / "app/Dyn.php").write_text("<?php\n$x = new $class();\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/LogTest.php").write_text("<?php\nuse Monolog\\Logger;\n")
    return tmp_path


def test_lock_dev_split_versions_and_platform(app):
    lock = composer.load(app)
    assert "laravel/framework@10.48.4" in lock.pkgs                 # `v` dropped for OSV
    assert lock.pkgs["phpunit/phpunit@10.5.0"].dev and not lock.pkgs["psr/log@3.0.0"].dev
    assert lock.pkgs["acme/local@dev-main"].local
    # case-insensitive, php/ext-* dropped
    assert lock.prod_roots == {"laravel/framework@10.48.4", "acme/local@dev-main", "psr/log@3.0.0"}
    assert lock.dev_roots == {"phpunit/phpunit@10.5.0"}
    assert lock.namespaces_of("symfony/http-kernel") == ["Symfony\\Component\\HttpKernel"]


def test_parse_composer_deps(app):
    deps = {d.name: d for d in osv.parse_composer(app)}
    assert "acme/local" not in deps                                  # path package: the app's own code
    assert deps["laravel/framework"].direct and deps["laravel/framework"].ecosystem == "Packagist"
    assert deps["phpunit/phpunit"].dev and not deps["monolog/monolog"].direct
    found, used = osv.find_deps(app)
    assert "composer.lock" in used and any(d.name == "psr/log" for d in found)
    assert osv._eco("Packagist") == "composer"
    assert names.same("Symfony/HTTP-Kernel", "symfony/http-kernel", "composer")


def test_chains_follow_require_and_replace(app):
    g = depgraph.load(app, "composer")
    assert ["laravel/framework@10.48.4", "symfony/http-kernel@6.4.5", "symfony/http-foundation@6.4.4"] in \
        depgraph.chains(g, "symfony/http-foundation", "6.4.4")
    # spatie/thing requires illuminate/support, which laravel/framework replaces
    assert "laravel/framework@10.48.4" in g.edges["spatie/thing@1.0.0"]
    assert g.nodes["psr/log@3.0.0"]["integrity"] == f"git+{GH.format('psr/log')}#{'a' * 40}"


def test_php_import_sites_by_namespace(app):
    u = usage_summary(str(app), "composer", "symfony/http-foundation", version="6.4.4")
    assert [s.split(":")[:2] for s in u.import_sites] == [["app/Kernel.php", "3"]]
    u = usage_summary(str(app), "composer", "monolog/monolog", version="3.5.0")
    sites = u.import_sites
    assert any(s.startswith("app/Kernel.php:5:") for s in sites)     # fully qualified \Monolog\...
    assert not any(":4:" in s and "Kernel" in s for s in sites)      # commented-out use
    assert any(s.startswith("tests/LogTest.php") and s.endswith("(test code)") for s in sites)
    u = usage_summary(str(app), "composer", "symfony/http-kernel", version="6.4.5")
    assert any(s.startswith("app/Kernel.php:6:") for s in u.import_sites)   # class-name string
    assert any(s.startswith("app/Dyn.php:2:") for s in u.dynamic_sites) and not u.closed_world


def test_composer_not_reachable_is_held_except_for_split(app, monkeypatch):
    # php4 lifted the hold for split, which still settles only with claude agreeing (test_judges)
    monkeypatch.delenv("SSVC_NR_UNMEASURED", raising=False)
    u = usage_summary(str(app), "composer", "psr/log", version="3.0.0")
    v, note = guard_not_reachable(Verdict.NOT_REACHABLE, u, "workstation")
    assert v == Verdict.UNSURE and "no measured floor for composer" in note
    assert guard_not_reachable(Verdict.NOT_REACHABLE, u, "split")[0] == Verdict.NOT_REACHABLE


def _git(*a, cwd):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a], cwd=cwd, check=True,
                   capture_output=True)


def test_git_extract_reads_only_the_pinned_tree(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    _git("init", "-q", ".", cwd=work)
    (work / "src").mkdir()
    (work / "src/Logger.php").write_text("<?php class Logger {}\n")
    (work / "README.md").write_text("not php\n")
    (work / "composer.json").write_text("{}\n")
    (work / "link.php").symlink_to("/etc/passwd")
    _git("add", "-A", cwd=work)
    _git("commit", "-q", "-m", "x", cwd=work)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=work, capture_output=True, text=True, check=True).stdout.strip()
    stats = pkgsrc._git_extract(work / ".git", sha, tmp_path / "out", pkgsrc.PHP_EXT)
    got = sorted(p.relative_to(tmp_path / "out").as_posix() for p in (tmp_path / "out").rglob("*") if p.is_file())
    assert got == ["composer.json", "src/Logger.php"]
    assert stats["skipped_type"] == 1 and stats["skipped_ext"] == 1     # the symlink, README
    with pytest.raises(pkgsrc.Rejected):
        pkgsrc._git_extract(work / ".git", "b" * 40, tmp_path / "out2", pkgsrc.PHP_EXT)


@pytest.mark.parametrize("integrity, why", [
    (f"git+https://evil.example/a/b.git#{'a' * 40}", "not in SSVC_COMPOSER_GIT_HOSTS"),
    (f"git+http://github.com/a/b.git#{'a' * 40}", "unusable git source"),
    ("git+https://github.com/a/b.git#main", "unusable git source"),
    (f"git+https://github.com/a/../b.git#{'a' * 40}", "unusable git source"),
    ("", "no pinned commit"),
])
def test_fetch_composer_refuses_unverifiable_sources(tmp_path, monkeypatch, integrity, why):
    monkeypatch.setenv("SSVC_PKGSRC_CACHE", str(tmp_path))
    with pytest.raises(pkgsrc.Rejected, match=why):
        pkgsrc.fetch_composer("a/b", "1.0.0", integrity)


def test_fetch_composer_asks_for_the_pinned_commit_once(tmp_path, monkeypatch):
    monkeypatch.setenv("SSVC_PKGSRC_CACHE", str(tmp_path))
    calls = []

    def fake_git(args, cwd, timeout, inp=None):
        calls.append(args)
        if args[0] == "fetch":
            raise pkgsrc.Rejected("stop")
        return b""
    monkeypatch.setattr(pkgsrc, "_git", fake_git)
    with pytest.raises(pkgsrc.Rejected, match="stop"):
        pkgsrc.fetch_composer("psr/log", "3.0.2", f"git+https://github.com/php-fig/log.git#{'c' * 40}")
    fetch = next(a for a in calls if a[0] == "fetch")
    assert fetch[-2:] == ["https://github.com/php-fig/log.git", "c" * 40]      # not log.git.git


def test_laravel_http_client_cookie_jar_note(app, monkeypatch):
    """A guzzle row in a Laravel app: the note names the installed framework's cookie default,
    checked in its source, and the app's Http:: call sites; other packages get no note."""
    from doublestrain.judges.phpclients import http_client_note
    lock = json.loads((app / "composer.lock").read_text())
    lock["packages"].append(_p("guzzlehttp/guzzle", "7.9.3", [], ["GuzzleHttp"]))
    (app / "composer.lock").write_text(json.dumps(lock))
    cache = app / "pkgsrc"
    src = cache / f"composer+laravel+framework@10.48.4-{'a' * 12}"
    (src / "src/Illuminate/Http/Client").mkdir(parents=True)
    (src / "src/Illuminate/Http/Client/PendingRequest.php").write_text(
        "<?php\n// 'cookies' => true in a comment\nreturn new Client([\n  'handler' => $h,\n  'cookies' => true,\n]);\n")
    src.with_name(src.name + ".json").write_text("{}")
    monkeypatch.setenv("SSVC_PKGSRC_CACHE", str(cache))
    monkeypatch.delenv("SSVC_PKGSRC", raising=False)
    (app / "app/Hook.php").write_text("<?php\nuse Illuminate\\Support\\Facades\\Http;\n$r = Http::withHeaders([])->post($u);\n")
    note = http_client_note(str(app), "composer", "guzzlehttp/guzzle", "7.9.3")
    assert "laravel/framework 10.48.4" in note and "PendingRequest.php:5" in note
    assert "app/Hook.php:3" in note and "app/Hook.php:2" in note
    assert http_client_note(str(app), "composer", "psr/log", "3.0.0") == ""
    u = usage_summary(str(app), "composer", "guzzlehttp/guzzle", version="7.9.3")
    assert u.framework == note and note.splitlines()[0] in u.text


def test_http_client_note_lists_installed_packages_that_call_laravels_client(app, monkeypatch):
    """php3: Lychee's only Http:: use was in an installed package (log-viewer). Package files count
    only when their Http is Laravel's facade or client; league/uri's own Http class does not."""
    from doublestrain.judges.phpclients import http_client_note
    lock = json.loads((app / "composer.lock").read_text())
    lock["packages"] += [_p("guzzlehttp/guzzle", "7.9.3", [], ["GuzzleHttp"]),
                         _p("opcodesio/log-viewer", "v3.1.0", [], ["Opcodes\\LogViewer"]),
                         _p("league/uri", "7.5.1", [], ["League\\Uri"])]
    (app / "composer.lock").write_text(json.dumps(lock))
    cache = app.parent / "pkgsrc"         # outside the app, which is scanned too
    fw = cache / f"composer+laravel+framework@10.48.4-{'a' * 12}"
    (fw / "src/Illuminate/Http/Client").mkdir(parents=True)
    (fw / "src/Illuminate/Http/Client/PendingRequest.php").write_text("<?php\nreturn new Client(['cookies' => true]);\n")
    lv = cache / f"composer+opcodesio+log-viewer@3.1.0-{'a' * 12}"
    (lv / "src/Http/Middleware").mkdir(parents=True)
    (lv / "src/Http/Middleware/Forward.php").write_text(
        "<?php\nnamespace Opcodes\\LogViewer;\nuse Illuminate\\Support\\Facades\\Http;\n$r = Http::withHeaders($h)->get($u);\n")
    (lv / "tests").mkdir()
    (lv / "tests/ForwardTest.php").write_text("<?php\nuse Illuminate\\Support\\Facades\\Http;\nHttp::fake();\n")
    uri = cache / f"composer+league+uri@7.5.1-{'a' * 12}"
    uri.mkdir(parents=True)
    (uri / "HttpFactory.php").write_text("<?php\nnamespace League\\Uri;\nreturn Http::new($uri);\n")
    for d in (fw, lv, uri):
        d.with_name(d.name + ".json").write_text("{}")
    monkeypatch.setenv("SSVC_PKGSRC_CACHE", str(cache))
    monkeypatch.delenv("SSVC_PKGSRC", raising=False)
    note = http_client_note(str(app), "composer", "guzzlehttp/guzzle", "7.9.3")
    assert "No call site of Laravel's HTTP client in the app source." in note
    assert "opcodesio/log-viewer 3.1.0: src/Http/Middleware/Forward.php:4: $r = Http::withHeaders" in note
    assert "league/uri" not in note and "ForwardTest" not in note


def test_composer_source_keeps_bundle_config_and_reextracts_php_only_caches(tmp_path, monkeypatch):
    import hashlib, io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in ("src/X.php", "Resources/config/validation.xml",
                  "Resources/views/x.html.twig", "README.md"):
            z.writestr(n, "x")
    data = buf.getvalue()
    sha = hashlib.sha1(data).hexdigest()
    monkeypatch.setenv("SSVC_PKGSRC_CACHE", str(tmp_path))
    old = tmp_path / f"composer+a+b@1.0.0-{sha[:12]}"
    (old / "src").mkdir(parents=True)
    (old / "src/X.php").write_text("old")
    old.with_name(old.name + ".json").write_text("{}")             # extracted before COMPOSER_KEEP
    monkeypatch.setattr(pkgsrc, "_get", lambda url, cap, timeout=60.0: data)
    d = pkgsrc.fetch_composer("a/b", "1.0.0", f"sha1:{sha} https://example.invalid/a.zip")
    assert d == old
    got = sorted(str(p.relative_to(d)) for p in d.rglob("*") if p.is_file())
    assert got == ["Resources/config/validation.xml", "Resources/views/x.html.twig", "src/X.php"]
    monkeypatch.setattr(pkgsrc, "_get", lambda *a, **k: pytest.fail("refetched a current cache"))
    assert pkgsrc.fetch_composer("a/b", "1.0.0", f"sha1:{sha} https://example.invalid/a.zip") == d
