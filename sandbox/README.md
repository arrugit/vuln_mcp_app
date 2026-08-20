# Sandbox plane (MCP05 execution) — foundation placeholder

The **sandbox** is the isolated, network-egress-free execution container used
**only** by the MCP05 `report.export` tool (TDD §20, SEC-003). It is created as a
distinct Docker Compose service on an **internal-only** network so nothing it
runs can reach the Internet (DECISION D-06 / SEC-005).

> **Phase 0 status:** the sandbox image + runner contract are scaffolded here.
> The actual command runner and the MCP05 unsafe/secure execution paths are
> implemented in the MCP05 lab phases. No execution happens in the foundation.

## Required isolation controls (SEC-003) — enforced by Compose

| Control | Setting |
|---|---|
| No outbound network | `sandbox-net` is `internal: true`; no `app-net` |
| Non-root | `user: "10001:10001"` |
| Read-only root FS | `read_only: true` |
| Ephemeral work dir | `tmpfs: ["/work"]` |
| Capability drop | `cap_drop: ["ALL"]` |
| PID limit | `pids_limit: 64` |
| Memory limit | `mem_limit: 256m` |
| Timeout | enforced by the caller (`SANDBOX_TIMEOUT_SECONDS`) |
| Allow-listed binaries | only the exec tool's permitted commands |

## Runner contract (to be implemented in MCP05)

The MCP server sends a **command spec** and receives output. In VULNERABLE mode
it passes a shell string (unsafe concatenation); in SECURE mode it passes an
`argv` list (no shell). The sandbox never has host access.

```
request:  { "argv": ["convert", "a.txt", "out.pdf"] }        # secure
          { "shell": "convert a.txt out.pdf" }               # vulnerable
response: { "exit_code": 0, "stdout": "...", "stderr": "...",
            "marker_present": false }
```

The blast radius **ends at the sandbox**: the injection is real, the damage is
contained (SEC-001).
