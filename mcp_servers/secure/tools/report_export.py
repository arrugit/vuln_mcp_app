"""Secure ``report.export`` tool — MCP05 lab, SECURE variant.

This is the *safe* implementation of the tool whose unsafe twin (added in
Phase B under ``mcp_servers/vulnerable/tools/report_export.py``) carries the
MCP05 Command Injection vulnerability.

Why this file is safe (SEC-007)
-------------------------------
1. **Input validation.** The ``filename`` is checked against an allow-list regex
   (``is_safe_filename``) that rejects every shell separator (`;`, `|`, `&`,
   `>`), spaces, and path separators. The documented injection payload fails
   this check and is rejected before anything runs.
2. **Parameterised execution (no shell).** Even for a valid filename, the tool
   runs the converter via ``argv`` with ``shell=False`` (``SandboxRunner.run_argv``).
   No shell ever interprets the argument, so metacharacters are inert.

The result therefore never creates the ``/work/marker`` side effect.
"""
from __future__ import annotations

from typing import Any, Dict

from mcp_servers.common.registry import Tool, ToolRegistry

CLEAN_REPORT_EXPORT_DEFINITION: Dict[str, Any] = {
    "name": "report.export",
    "description": "Export a synthetic report by converting an input file to PDF in the sandbox.",
    "inputSchema": {
        "type": "object",
        "properties": {"filename": {"type": "string"}},
        "required": ["filename"],
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "ok": {"type": "boolean"},
            "rejected": {"type": "boolean"},
            "marker_present": {"type": "boolean"},
            "constructed_command": {"type": "string"},
            "stdout": {"type": "string"},
        },
    },
}


def clean_report_export(args: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the filename, then run the converter via argv (no shell)."""
    from labs.mcp05_command_injection.fixtures import is_safe_filename
    from sandbox.runner import SandboxRunner

    filename = str(args.get("filename", ""))

    # Control #1: reject anything that is not an allow-listed filename.
    if not is_safe_filename(filename):
        return {
            "ok": False,
            "rejected": True,
            "reason": "filename failed allow-list validation",
            "marker_present": False,
            "constructed_command": None,
            "stdout": "",
            "mode": "secure",
        }

    # Control #2: parameterised (argv) execution — no shell interprets the input.
    with SandboxRunner() as sandbox:
        result = sandbox.run_argv(sandbox.convert_argv(filename))
        return {
            "ok": result.exit_code == 0,
            "rejected": False,
            "marker_present": result.marker_present,  # always False in secure mode
            "constructed_command": result.constructed_command,
            "stdout": result.stdout,
            "exit_code": result.exit_code,
            "mode": "secure",
        }


def register_report_export(registry: ToolRegistry) -> None:
    """Register the secure report.export tool (idempotent-safe)."""
    if registry.has("report.export"):
        return
    registry.register(
        Tool(
            name="report.export",
            description=CLEAN_REPORT_EXPORT_DEFINITION["description"],
            input_schema=CLEAN_REPORT_EXPORT_DEFINITION["inputSchema"],
            output_schema=CLEAN_REPORT_EXPORT_DEFINITION["outputSchema"],
            handler=clean_report_export,
            risk="none",
            trust_status="trusted",
        )
    )
