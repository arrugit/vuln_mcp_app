"""Constrained in-process subprocess sandbox runner (MCP05, D-08).

This replaces the old Docker container sandbox (removed with Docker). It executes
at most a single allow-listed fake command (``fake_convert.py``) inside an
**ephemeral temporary work directory**, with a hard timeout and truncated output.

Controls (SEC-003, as realised without containers — see ``sandbox/README.md``):

* **Ephemeral work dir** — a fresh ``tempfile.mkdtemp()`` per run, deleted on
  exit. The virtual path ``/work`` in a command is translated to this real dir,
  emulating a container bind-mount without needing one.
* **Allow-list** — the only program ever invoked is our fake ``convert`` shim
  (via the current Python interpreter). No real system binaries are called in the
  secure path.
* **Timeout** — a hard wall-clock kill (``SANDBOX_TIMEOUT_SECONDS``).
* **Output cap** — stdout/stderr truncated so a runaway cannot flood memory.
* **Minimal environment** — the child gets a small, scrubbed env.

Phase A implements ONLY the SAFE primitive :meth:`SandboxRunner.run_argv`
(``shell=False``). The unsafe shell path used to demonstrate injection is added
in MCP05 Phase B (:meth:`run_shell`) — it does not exist here yet, so the
foundation ships with no exploitable behaviour.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# The virtual work-dir token used in lab payloads (emulated bind-mount point).
WORK_TOKEN = "/work"
# Name of the side-effect marker file the injection payload tries to create.
MARKER_NAME = "marker"
# Default hard timeout (seconds); overridable via env for the lab config.
DEFAULT_TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT_SECONDS", "5"))
# Cap on captured output length (chars) to avoid unbounded memory use.
_OUTPUT_CAP = 4000

# Absolute path to the fake convert shim (the only allow-listed program).
FAKE_CONVERT = str(Path(__file__).resolve().parent / "fake_convert.py")


@dataclass
class SandboxResult:
    """Outcome of one sandboxed execution."""

    exit_code: Optional[int]
    stdout: str
    stderr: str
    marker_present: bool
    timed_out: bool
    # The exact command the tool constructed (string for shell path, or the
    # argv joined for display). Recorded as MCP05 evidence.
    constructed_command: str


def find_posix_shell() -> Optional[str]:
    """Locate a POSIX shell for the (Phase B) unsafe path.

    Order: ``LAB_SHELL`` env override, then ``bash``/``sh`` on PATH, then the
    Git-for-Windows default locations. Returns ``None`` if none is found. Kept
    here in Phase A so the contract is stable; the vulnerable tool in Phase B
    uses it.
    """
    override = os.environ.get("LAB_SHELL")
    if override and Path(override).exists():
        return override
    for name in ("bash", "sh"):
        found = shutil.which(name)
        if found:
            return found
    for candidate in (
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ):
        if Path(candidate).exists():
            return candidate
    return None


def _minimal_env() -> dict:
    """A small, scrubbed environment for the child process."""
    keep = {}
    path = os.environ.get("PATH")
    if path:
        keep["PATH"] = path
    # SystemRoot is required for subprocess on Windows.
    if os.name == "nt" and os.environ.get("SystemRoot"):
        keep["SystemRoot"] = os.environ["SystemRoot"]
    return keep


def _truncate(text: str) -> str:
    if len(text) > _OUTPUT_CAP:
        return text[:_OUTPUT_CAP] + "…[truncated]"
    return text


class SandboxRunner:
    """Context-managed ephemeral work dir + execution primitives.

    Usage::

        with SandboxRunner() as sb:
            result = sb.run_argv(sb.convert_argv("a.txt"))
    """

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout
        self.workdir: Optional[str] = None

    def __enter__(self) -> "SandboxRunner":
        self.workdir = tempfile.mkdtemp(prefix="mcp05_work_")
        return self

    def __exit__(self, *exc) -> None:
        if self.workdir:
            shutil.rmtree(self.workdir, ignore_errors=True)
            self.workdir = None

    # -- helpers ---------------------------------------------------------
    def _require_workdir(self) -> str:
        if not self.workdir:
            raise RuntimeError("SandboxRunner must be used as a context manager")
        return self.workdir

    def _translate(self, text: str) -> str:
        """Map the virtual ``/work`` token onto the real ephemeral dir.

        Uses forward slashes so the result is valid both for argv on any OS and
        inside a POSIX shell command.
        """
        wd = self._require_workdir().replace("\\", "/")
        return text.replace(WORK_TOKEN, wd)

    @property
    def marker_path(self) -> Path:
        return Path(self._require_workdir()) / MARKER_NAME

    def marker_present(self) -> bool:
        return self.marker_path.exists()

    def convert_argv(self, filename: str, out_name: str = "out.pdf") -> List[str]:
        """Build the SAFE argv for the fake convert: python shim + literal args.

        The filename is passed as a single argv element, so shell metacharacters
        in it are inert (this is the secure execution model).
        """
        return [sys.executable, FAKE_CONVERT, filename, out_name]

    # -- SAFE primitive (Phase A) ----------------------------------------
    def run_argv(self, argv: List[str]) -> SandboxResult:
        """Execute ``argv`` with ``shell=False`` inside the work dir.

        No shell is involved, so no metacharacter is ever interpreted. This is
        the secure execution path (SEC-007). ``/work`` tokens in any argument are
        translated to the ephemeral dir.
        """
        wd = self._require_workdir()
        translated = [self._translate(a) for a in argv]
        timed_out = False
        try:
            proc = subprocess.run(
                translated,
                cwd=wd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=_minimal_env(),
                shell=False,  # <-- the security control: never a shell
            )
            exit_code: Optional[int] = proc.returncode
            stdout, stderr = proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = None
            stdout = exc.stdout or ""
            stderr = (exc.stderr or "") + "\n[sandbox] timed out"
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")

        return SandboxResult(
            exit_code=exit_code,
            stdout=_truncate(stdout),
            stderr=_truncate(stderr),
            marker_present=self.marker_present(),
            timed_out=timed_out,
            # For display, show the argv the tool ran (secure path has no shell
            # string). Uses the untranslated form so evidence is human-readable.
            constructed_command=" ".join(argv),
        )

    # -- UNSAFE primitive (MCP05 Phase B) --------------------------------
    def run_shell(self, cmd: str) -> SandboxResult:
        """Execute ``cmd`` THROUGH A POSIX SHELL — the unsafe path.

        This is the primitive the VULNERABLE ``report.export`` uses. A shell
        parses the string, so any shell metacharacter in the (untrusted) input
        that was concatenated into ``cmd`` is interpreted — that is the command
        injection. Containment is preserved by the sandbox controls: it runs in
        the ephemeral work dir, only a fake ``convert`` (a shell function
        prelude) is available, output is capped, and a hard timeout applies.

        ``constructed_command`` records the RAW unsafe string (``/work``
        untranslated) so the evidence shows the injected separator exactly.
        """
        wd = self._require_workdir()
        shell = find_posix_shell()
        if shell is None:  # pragma: no cover - environment-dependent
            raise RuntimeError(
                "no POSIX shell found for sandbox shell execution; set LAB_SHELL"
            )
        translated = self._translate(cmd)
        # A fake 'convert' so the legitimate part of the command "works" without
        # a real converter; the shell still interprets any injected metacharacters.
        prelude = 'convert() { : > "${2:-out.pdf}"; echo "converted $1 -> ${2:-out.pdf}"; }; '
        full = prelude + translated
        timed_out = False
        try:
            proc = subprocess.run(
                [shell, "-c", full],
                cwd=wd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=_minimal_env(),
                shell=False,  # we invoke the shell explicitly with an argv
            )
            exit_code: Optional[int] = proc.returncode
            stdout, stderr = proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = None
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = (exc.stderr if isinstance(exc.stderr, str) else "") + "\n[sandbox] timed out"

        return SandboxResult(
            exit_code=exit_code,
            stdout=_truncate(stdout),
            stderr=_truncate(stderr),
            marker_present=self.marker_present(),
            timed_out=timed_out,
            constructed_command=cmd,  # raw unsafe string (the sink), untranslated
        )


def main() -> None:  # pragma: no cover - manual smoke helper
    """Manual smoke test: run the fake convert on a benign filename."""
    with SandboxRunner() as sb:
        result = sb.run_argv(sb.convert_argv("a.txt"))
        print("exit", result.exit_code, "marker", result.marker_present)
        print(result.stdout.strip())


if __name__ == "__main__":
    main()
