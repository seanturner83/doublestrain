"""imagedeps: the dependency groups, extras and requirements files the app's image installs.

pylock calls a group, extra or requirements file named like dev/test development. py8's Redash
image runs `poetry install --only main,all_ds,dev` (the `dev` group is in production) and Label
Studio's runs a bare `poetry install` (every non-optional group): both were scanned by hand.

This reads the Dockerfiles under the lock's directory (text only; nothing is built or run). The
default build target is the last stage; the stages it is built on (FROM) or copies from
(COPY --from) count, the others (testing, development) don't. Dockerfiles named like dev/test
are skipped. In those stages it reads `poetry install` (--only / --with / --without / --extras),
`uv sync` (--group / --only-group / --all-groups / --no-dev / --no-default-groups / --extra) and
`pip install` (`.[extras]`, -r files), with ARG defaults substituted. Several Dockerfiles, or
both arms of a shell `if`, are a union. Widening only: what an image installs becomes
production; nothing here makes a production dependency development.
"""
from __future__ import annotations

import functools
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from .approots import _dockerfiles, _instructions

_DEVFILE = re.compile(r"(^|[-_.])(dev|develop|development|test|tests|testing|ci)($|[-_.])", re.I)
_ENV = re.compile(r"site-packages|dist-packages|venv|virtualenv|/usr/local/(?:lib|bin)\b|/usr/local/?\s|\.local\b|wheels?\b")
_ARG = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}?")


@dataclass
class Installed:
    poetry: list[tuple[frozenset | None, frozenset, frozenset]] = field(default_factory=list)  # (only, with, without)
    uv_groups: set[str] = field(default_factory=set)     # "*" = every group
    extras: set[str] = field(default_factory=set)        # "*" = every extra
    req_files: set[str] = field(default_factory=set)     # basenames

    def extra(self, name: str) -> bool:
        return "*" in self.extras or _norm(name) in self.extras

    def uv_group(self, name: str) -> bool:
        return "*" in self.uv_groups or _norm(name) in self.uv_groups

    def req_closure(self, files) -> set[str]:
        """Basenames of the requirements files installed, following `-r` includes."""
        by_name = {Path(f).name: Path(f) for f in files}
        seen, todo = set(), [n for n in self.req_files if n in by_name]
        while todo:
            n = todo.pop()
            if n in seen:
                continue
            seen.add(n)
            try:
                text = by_name[n].read_text(errors="replace")
            except OSError:
                continue
            for m in re.finditer(r"^\s*(?:-r|--requirement)[=\s]+(\S+)", text, re.M):
                if (inc := Path(m.group(1)).name) in by_name:
                    todo.append(inc)
        return seen

    def poetry_group(self, group: str, optional: bool) -> bool:
        """Does some `poetry install` here install this group?"""
        g = group.lower()
        for only, with_, without in self.poetry:
            if only is not None:
                if g in only:
                    return True
            elif g in with_ or (not optional and g not in without):
                return True
        return False


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _names(v: str) -> set[str]:
    return {_norm(x) for x in re.split(r"[,\s]+", v.strip("\"'")) if x}


def _stages(text: str):
    """[(name, base, [(KEYWORD, rest)])], ARG defaults before the first FROM applied."""
    glob_args, stages = {}, []
    for kw, rest in _instructions(text):
        if kw == "FROM":
            a = [x for x in rest.split() if not x.startswith("--")]
            name = a[2].lower() if len(a) >= 3 and a[1].lower() == "as" else ""
            stages.append((name, (a[0].lower() if a else ""), []))
        elif kw == "ARG" and not stages:
            k, _, v = rest.partition("=")
            glob_args[k.strip()] = v.strip().strip("\"'")
        elif stages:
            stages[-1][2].append((kw, rest))
    return glob_args, stages


def _target(stages) -> list[int]:
    """Indexes of the stages the default target (the last) is built on or copies from."""
    by_name = {n: i for i, (n, _b, _ins) in enumerate(stages) if n}
    keep, todo = set(), [len(stages) - 1] if stages else []
    while todo:
        i = todo.pop()
        if i in keep:
            continue
        keep.add(i)
        name, base, ins = stages[i]
        # a stage copied from counts when what's copied is an environment (Nautobot's final
        # image copies site-packages from python-dependencies, but only a config file from
        # final-dev; Mathesar's copies static files from development)
        deps = [base] + [m.group(1).lower() for kw, rest in ins if kw in ("COPY", "ADD")
                         for m in [re.search(r"--from=(\S+)", rest)] if m and _ENV.search(rest)]
        todo += [by_name[d] for d in deps if d in by_name and by_name[d] < i]
    return sorted(keep)


_ALT = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):\+([^}]*)\}")


def _subst(s: str, args: dict) -> str:
    # ${X:+alt}: alt when X is set and non-empty, else nothing (Qdrant: ${FEATURES:+--features})
    s = _ALT.sub(lambda m: m.group(2) if args.get(m.group(1)) else ("" if m.group(1) in args else m.group(0)), s)
    return _ARG.sub(lambda m: args.get(m.group(1), m.group(2) if m.group(2) is not None else m.group(0)), s)


def _after(a: list[str], tool: tuple[str, ...], verb: str) -> list[str] | None:
    """The arguments after `<tool> ... <verb>` (`/etc/poetry/bin/poetry install`,
    `python -m pip install`, `uv pip install`), or None when this command isn't one."""
    for n, t in enumerate(a):
        if Path(t).name in tool and verb in a[n + 1:]:
            return a[a.index(verb, n + 1) + 1:]
    return None


def _opts(a: list[str]):
    """(flag, value) pairs: `--only=a,b` and `--only a,b` alike."""
    for n, x in enumerate(a):
        k, eq, v = x.partition("=")
        yield k, (v if eq else (a[n + 1] if n + 1 < len(a) else ""))


def _read_run(cmd: str, out: Installed) -> None:
    for part in re.split(r"&&|;|\|\||\bthen\b|\belse\b|\bfi\b", cmd):
        try:
            a = shlex.split(part)
        except ValueError:
            a = part.split()
        if (args := _after(a, ("poetry",), "install")) is not None:
            only, with_, without = None, set(), set()
            for k, v in _opts(args):
                if k == "--only":
                    only = (only or set()) | _names(v)
                elif k == "--with":
                    with_ |= _names(v)
                elif k == "--without":
                    without |= _names(v)
                elif k in ("--no-dev", "--only-root"):
                    only = only or {"main"}
                elif k in ("--extras", "-E"):
                    out.extras |= _names(v)
                elif k == "--all-extras":
                    out.extras.add("*")
            out.poetry.append((frozenset(only) if only is not None else None, frozenset(with_), frozenset(without)))
        elif (args := _after(a, ("uv",), "sync")) is not None:
            groups = {"dev"}                    # uv sync installs the default groups (dev) unless told not to
            for k, v in _opts(args):
                if k in ("--no-dev", "--no-default-groups"):
                    groups.discard("dev")
                elif k in ("--group", "--only-group"):
                    groups |= _names(v)
                elif k == "--all-groups":
                    groups.add("*")
                elif k == "--extra":
                    out.extras |= _names(v)
                elif k == "--all-extras":
                    out.extras.add("*")
            out.uv_groups |= groups
        elif (args := _after(a, ("pip", "pip3"), "install")) is not None:
            for n, x in enumerate(args):
                if n and args[n - 1] in ("-r", "--requirement"):
                    out.req_files.add(Path(x).name)
                elif x.startswith("--requirement="):
                    out.req_files.add(Path(x.split("=", 1)[1]).name)
                elif x.startswith("-r") and len(x) > 2:
                    out.req_files.add(Path(x[2:]).name)
                elif m := re.match(r"^[./\w-]*\[([^\]]+)\]$", x):
                    out.extras |= _names(m.group(1))


@functools.lru_cache(maxsize=64)
def _installed(root: str) -> Installed:
    out = Installed()
    for df in _dockerfiles(Path(root)):
        suffix = df.name.replace("Dockerfile", "")
        if _DEVFILE.search(suffix) or _DEVFILE.search(df.parent.name if df.parent != Path(root) else ""):
            continue
        try:
            glob_args, stages = _stages(df.read_text(errors="replace"))
        except OSError:
            continue
        for i in _target(stages):
            args = dict(glob_args)
            for kw, rest in stages[i][2]:
                if kw == "ARG":
                    # a stage's ARG without a value inherits the global default, else ""
                    k, eq, v = rest.partition("=")
                    args[k.strip()] = v.strip().strip("\"'") if eq else glob_args.get(k.strip(), "")
                elif kw == "ENV":
                    for k, v in re.findall(r"([A-Za-z_]\w*)=(\"[^\"]*\"|\S+)", rest):
                        args[k] = _subst(v.strip("\"'"), args)
                elif kw == "RUN":
                    _read_run(_subst(rest, args), out)
    return out


def installed(repo: str | Path) -> Installed:
    """What the image built from the Dockerfiles under `repo` installs (empty when none say)."""
    return _installed(str(Path(repo).expanduser().resolve()))


# --- cargo: which workspace packages and features the image compiles --------------------

@dataclass(frozen=True)
class CargoBuild:
    packages: tuple[str, ...] = ()    # -p / --package (empty: the root package, or every member)
    bins: tuple[str, ...] = ()        # --bin
    paths: tuple[str, ...] = ()       # cargo install --path
    features: tuple[str, ...] = ()    # --features / -F ("pkg/feat" allowed)
    no_default: bool = False
    all_features: bool = False
    workspace: bool = False


def _cargo_cmd(a: list[str]) -> CargoBuild | None:
    for verb in ("build", "install", "run", "rustc"):
        if (args := _after(a, ("cargo", "xx-cargo", "cross"), verb)) is not None:      # xx-cargo: cross builds
            break
    else:
        return None
    if verb == "install" and "--path" not in " ".join(args):
        return None            # `cargo install --git ... tool` / `cargo install sccache`: not this workspace
    pk, bins, paths, feats = [], [], [], []
    no_def = all_f = ws = False
    for k, v in _opts(args):
        if k in ("-p", "--package"):
            pk.append(v)
        elif k == "--bin":
            bins.append(v)
        elif k == "--path":
            paths.append(v)
        elif k in ("--features", "-F"):
            feats += [f for f in re.split(r"[,\s]+", v.strip("\"'")) if f]
        elif k == "--no-default-features":
            no_def = True
        elif k == "--all-features":
            all_f = True
        elif k in ("--workspace", "--all"):
            ws = True
    return CargoBuild(tuple(pk), tuple(bins), tuple(paths), tuple(feats), no_def, all_f, ws)


@functools.lru_cache(maxsize=64)
def _cargo_builds(root: str) -> tuple[CargoBuild, ...]:
    out = []
    for df in _dockerfiles(Path(root)):
        suffix = df.name.replace("Dockerfile", "")
        if _DEVFILE.search(suffix):
            continue
        try:
            glob_args, stages = _stages(df.read_text(errors="replace"))
        except OSError:
            continue
        # every stage: Rust images build in one stage and copy the binary out of it
        for _name, _base, ins in stages:
            args = dict(glob_args)
            for kw, rest in ins:
                if kw == "ARG":
                    # a stage's ARG without a value inherits the global default, else ""
                    k, eq, v = rest.partition("=")
                    args[k.strip()] = v.strip().strip("\"'") if eq else glob_args.get(k.strip(), "")
                elif kw == "ENV":
                    for k, v in re.findall(r"([A-Za-z_]\w*)=(\"[^\"]*\"|\S+)", rest):
                        args[k] = _subst(v.strip("\"'"), args)
                elif kw == "RUN":
                    for part in re.split(r"&&|;|\|\||\bthen\b|\belse\b|\bfi\b", _subst(rest, args)):
                        try:
                            a = shlex.split(part)
                        except ValueError:
                            a = part.split()
                        if (b := _cargo_cmd(a)) is not None and b not in out:
                            out.append(b)
    return tuple(out)


def cargo_builds(repo: str | Path) -> tuple[CargoBuild, ...]:
    """The `cargo build` / `cargo install` commands the Dockerfiles under `repo` run (any stage)."""
    return _cargo_builds(str(Path(repo).expanduser().resolve()))
