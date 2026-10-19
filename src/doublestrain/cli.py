"""doublestrain <command> [args]: one entry point for the tools.

The `ssvc-*` commands remain as aliases (ssvc-scan == doublestrain scan, ...)."""
from __future__ import annotations

import importlib
import sys

COMMANDS = {
    "scan": ("doublestrain.scan", "grade one repo's dependency advisories end to end"),
    "run": ("doublestrain.harness.run", "run a judge over the labelled cases"),
    "score": ("doublestrain.harness.score", "score a run directory"),
    "compare": ("doublestrain.harness.compare", "compare two runs"),
    "shapes": ("doublestrain.judges.shape", "print the call shapes the shape tier would send"),
    "nofix": ("doublestrain.nofix", "advisories with no fixed version"),
    "watch": ("doublestrain.watch", "watch upstream fixes for open advisories"),
    "mitigate": ("doublestrain.mitigate", "mitigation notes for unfixable advisories"),
    "usage": ("doublestrain.accounting", "summarise the model-call ledger"),
}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help") or argv[0] not in COMMANDS:
        width = max(map(len, COMMANDS))
        print("usage: doublestrain <command> [args]\n\ncommands:")
        for name, (_mod, what) in COMMANDS.items():
            print(f"  {name:<{width}}  {what}")
        return 0 if argv and argv[0] in ("-h", "--help", "help") else 2
    mod = importlib.import_module(COMMANDS[argv[0]][0])
    sys.argv = [f"doublestrain {argv[0]}", *argv[1:]]
    return mod.main(argv[1:]) or 0


if __name__ == "__main__":
    sys.exit(main())
