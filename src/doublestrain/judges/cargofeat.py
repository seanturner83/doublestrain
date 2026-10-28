"""cargofeat as a judge tier: is the advisory's crate compiled into the deployed binary?

Package level, like jelly for npm and pyimports for PyPI (see `doublestrain.cargofeat` for
the resolution):

- the crate (that locked version) is compiled into the binary the image builds -> `unsure`:
  being linked in says nothing about the vulnerable function;
- it is locked but not compiled (an optional dependency no enabled feature turns on, a
  target the image isn't built for, a build-time crate's dependency, a workspace package
  the image doesn't build) -> not_reachable 1.0, with the edge that isn't taken.
  floors.toml marks it `corroborate`: a second tier must agree.

Everything is read as data (manifests from the checkout and from verified .crate files);
nothing is built and no build script runs. Only crate names and versions leave the machine.
"""
from __future__ import annotations

import time
from pathlib import Path

from .. import cargo, cargofeat, pkgsrc
from .base import JudgeResult, ReachQuery, Verdict


class CargoFeatJudge:
    name = "cargofeat"

    def fingerprint(self) -> str:
        return f"cargofeat@{cargofeat.RESOLVE_V}"

    def query_salt(self, q: ReachQuery) -> str:
        # the answer depends on the manifests, the lock and the Dockerfiles: keyed on them
        if q.ecosystem != "cargo":
            return ""
        return "-f" + cargofeat._key(Path(q.repo_path).expanduser())[:8]

    def app_code_destination(self) -> str:
        return "machine"

    def probe(self) -> tuple[bool, str]:
        if not pkgsrc.enabled():
            return False, "needs dependency source (SSVC_PKGSRC=1 / --pkgsrc)"
        return True, "Cargo feature resolution over the manifests (nothing built)"

    def judge(self, q: ReachQuery) -> JudgeResult | None:
        if q.ecosystem != "cargo" or not pkgsrc.enabled():
            return None
        root = Path(q.repo_path).expanduser()
        ws = cargo.load(root)
        if ws is None:
            return None
        targets = [cid for cid, c in ws.crates.items() if c.name == q.dependency
                   and (not q.version or c.version == q.version) and cid not in ws.members]
        if not targets:
            return None
        t0 = time.monotonic()
        a = cargofeat.analyse(root)
        if a is None:
            return None

        def res(verdict, conf, why):
            return JudgeResult(verdict, conf, self.name, rationale=why[:1200], latency_s=round(time.monotonic() - t0, 3),
                               cost_usd=0.0, model=f"cargofeat@{cargofeat.RESOLVE_V}")

        compiled = set(a["compiled"])
        roots = ", ".join(sorted({r.split("@")[0] for r in a["roots"]}))
        if hit := [t for t in targets if t in compiled]:
            return res(Verdict.UNSURE, 0.0, f"cargofeat: {hit[0]} is compiled into the deployed binary ({roots}); "
                                            "crate level only, so nothing about the vulnerable function")
        why = "; ".join(f"{t}: {a['why'].get(t, 'not compiled')}" for t in targets)
        return res(Verdict.NOT_REACHABLE, 1.0, f"cargofeat: not compiled into the deployed binary ({roots}). {why}")
