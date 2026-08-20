"""Synthetic fixtures for the MCP05 Command Injection lab.

All values are synthetic (SEC-002). Phase A uses only the safe pieces; the
poisoned payload constant is defined here so the write-up, the UI pre-fill, and
the Phase B security tests share one source of truth.
"""
from __future__ import annotations

import re

# The documented injection payload (FR-051a / GT-005). A benign leading filename
# (`a.txt`) followed by a shell separator and an extra command that writes a
# marker into the sandbox's /work dir. Deterministic in a POSIX shell.
INJECTION_PAYLOAD = "a.txt; echo PWNED > /work/marker"

# A plain, valid filename used for the safe/legit path.
SAFE_FILENAME = "a.txt"

# Secure-mode validation: allow-list of safe filename characters only. This
# regex rejects spaces, ';', '|', '&', '>', '/', etc. — i.e. every separator the
# injection relies on. Used by the SECURE report.export handler.
FILENAME_ALLOWLIST = re.compile(r"^[A-Za-z0-9._-]+$")

# The marker the payload tries to create (virtual path; the sandbox maps /work).
MARKER_VIRTUAL_PATH = "/work/marker"


def is_safe_filename(filename: str) -> bool:
    """Return True only for allow-listed filenames (secure-mode validation).

    Empty strings and anything containing a shell metacharacter or path
    separator are rejected — the payload above fails this check.
    """
    return bool(FILENAME_ALLOWLIST.match(filename or ""))
