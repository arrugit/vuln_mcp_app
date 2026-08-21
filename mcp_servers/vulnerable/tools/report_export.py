# INTENTIONALLY VULNERABLE — VULN-MCP05-001 — see docs/GROUND-TRUTH.md
"""Unsafe ``report.export`` tool — MCP05 Command Injection (VULNERABLE variant).

WHAT IS VULNERABLE HERE
-----------------------
The handler builds a shell command by **string concatenation** of an untrusted
argument and runs it **through a shell**:

    cmd = "convert " + filename + " out.pdf"   # <-- unsafe construction (the sink)
    sandbox.run_shell(cmd)                       # <-- a shell parses `cmd`

Because a shell parses the string, shell metacharacters in ``filename`` are
interpreted. The documented payload

    a.txt; echo PWNED > /work/marker

turns the single intended command into two: the (fake) ``convert a.txt`` **and**
an injected ``echo PWNED > /work/marker`` that creates a side-effect marker file.

WHY THIS IS INSECURE
--------------------
Untrusted input must never be concatenated into a shell string. The secure
variant (``mcp_servers/secure/tools/report_export.py``) validates the filename
against an allow-list AND executes via ``argv`` with ``shell=False``, so the same
payload is an inert literal.

BLAST RADIUS (SEC-001/003)
--------------------------
Execution is confined to the constrained in-process sandbox: an ephemeral temp
work dir, only a fake ``convert`` shell function is available, a hard timeout,
and capped output. The marker is created inside the throwaway dir — never on the
host proper. All data is synthetic (SEC-002).
"""
from __future__ import annotations

from typing import Any, Dict

from mcp_servers.common.registry import Tool, ToolRegistry

# The stored "unsafe" definition. Its description reveals the shell construction
# so the trusted-vs-unsafe diff (FR-013) is visible; the real flaw is in the
# handler below, not the metadata (contrast MCP03, where metadata IS the flaw).
UNSAFE_REPORT_EXPORT_DEFINITION: Dict[str, Any] = {
    "name": "report.export",
    "description": (
        "Export a report by running the shell command 'convert <filename> "
        "out.pdf' in the sandbox (filename concatenated directly)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"filename": {"type": "string"}},
        "required": ["filename"],
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "ok": {"type": "boolean"},
            "marker_present": {"type": "boolean"},
            "constructed_command": {"type": "string"},
            "stdout": {"type": "string"},
        },
    },
}


def unsafe_report_export(args: Dict[str, Any]) -> Dict[str, Any]:
    """Vulnerable handler: concatenate untrusted input into a shell command."""
    from sandbox.runner import SandboxRunner

    filename = str(args.get("filename", ""))

    with SandboxRunner() as sandbox:
        # Build the conversion command and run it. The filename is interpolated
        # straight into the command string, which is then executed by a shell —
        # so a filename containing shell metacharacters injects extra commands.
        cmd = "convert " + filename + " out.pdf"
        result = sandbox.run_shell(cmd)
        return {
            "ok": result.exit_code == 0,
            "rejected": False,
            "marker_present": result.marker_present,
            "constructed_command": result.constructed_command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
            "mode": "vulnerable",
        }


def register_unsafe_report_export(registry: ToolRegistry) -> None:
    """Register the UNSAFE report.export (vulnerable mode only)."""
    if registry.has("report.export"):
        registry.unregister("report.export")
    registry.register(
        Tool(
            name="report.export",
            description=UNSAFE_REPORT_EXPORT_DEFINITION["description"],
            input_schema=UNSAFE_REPORT_EXPORT_DEFINITION["inputSchema"],
            output_schema=UNSAFE_REPORT_EXPORT_DEFINITION["outputSchema"],
            handler=unsafe_report_export,
            risk="high",
            trust_status="poisoned",  # generic "unsafe version" marker (FR-013)
        )
    )
