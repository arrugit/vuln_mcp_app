"""Fake ``convert`` shim (the ONLY program the sandbox ever executes).

The MCP05 lab pretends ``report.export`` shells out to an image/doc converter
(like ImageMagick's ``convert``). We never run a real converter — this stub
stands in for it so the lab needs no system binaries and has nothing dangerous
to abuse (SEC-003 allow-list of exactly one fake command).

Behaviour: given ``<src> <dst>``, it writes a tiny placeholder "PDF" to ``dst``
and prints a line. It has NO concept of a marker and never writes anywhere except
its explicit ``dst`` argument — so in the SECURE (argv, no-shell) path a
malicious "filename" is just an inert literal and nothing extra happens.
"""
from __future__ import annotations

import pathlib
import sys


def main() -> int:
    args = sys.argv[1:]
    if len(args) < 2:
        print("usage: convert <src> <dst>")
        return 2
    src, dst = args[0], args[1]
    try:
        pathlib.Path(dst).write_text(f"FAKE PDF generated from {src!r}\n", encoding="utf-8")
    except OSError as exc:  # pragma: no cover - defensive
        print(f"convert: could not write {dst}: {exc}")
        return 1
    print(f"converted {src} -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
