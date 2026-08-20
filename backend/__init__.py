"""vuln_mcp_app backend package (control plane).

The control plane is *ordinarily-secure infrastructure* (TDD SEC-004): it applies
normal input validation, error handling, and localhost binding. It hosts labs and
emits evidence — it is NOT the vulnerable surface and NOT a scanner.
"""
