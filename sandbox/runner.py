"""Sandbox runner (Phase 0 placeholder).

The real command runner (accepting a command spec and executing allow-listed
binaries inside ``/work`` under the SEC-003 controls) is implemented in the MCP05
lab phases. In the foundation this process simply stays alive so the Compose
``sandbox`` service is a valid, isolated container with NO execution surface yet.

Security posture (already enforced by Compose, TDD §28):
  * no network (internal-only network, no default egress);
  * non-root user; read-only root FS; tmpfs /work; all caps dropped.
"""
from __future__ import annotations

import time


def main() -> None:
    print("[sandbox] foundation placeholder — no execution surface yet", flush=True)
    # Idle. The MCP05 phase replaces this with the guarded command runner.
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
