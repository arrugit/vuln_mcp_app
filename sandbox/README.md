# Sandbox plane (MCP05 execution) — revised for the Docker-free run model

The **sandbox** is the constrained execution environment used **only** by the
MCP05 `report.export` tool (implemented in the MCP05 phases). It exists so the
command-injection vulnerability can be demonstrated with a **contained blast
radius** (SEC-001/003).

> **Design change (2026-08-21):** Docker was removed from the project (the owner
> runs the app with `uvicorn`, not `docker compose`). The sandbox is therefore
> **no longer a container**; it becomes a **constrained in-process subprocess
> runner**. This is a deliberate trade-off — see below.

## Revised sandbox: constrained subprocess runner (planned for MCP05)

When MCP05 is built, `report.export` will call a small runner that executes an
allow-listed command inside an **ephemeral temporary work directory** (the
`/work` equivalent). Controls:

| Control | How (subprocess runner) |
|---|---|
| Ephemeral work dir | fresh `tempfile.mkdtemp()` per run; wiped on reset |
| Allow-listed command | only a **project-provided fake `convert` shim** (a Python script we ship) — never real system binaries |
| Timeout | hard `SANDBOX_TIMEOUT_SECONDS` kill |
| Output cap | stdout/stderr truncated |
| No shell in secure mode | secure path uses `subprocess.run([...], shell=False)` (argv) |
| Synthetic only | all inputs/outputs are fake; the "marker" is written inside the temp dir |

The **injection is real** (vulnerable mode uses `shell=True` string
concatenation, so `a.txt; echo PWNED > marker` creates the marker), but the
**damage is confined** to the throwaway temp directory.

## Trade-off vs. the old Docker sandbox (be explicit)

Docker previously provided OS-level guarantees: `--network none`, non-root,
read-only root FS, `--cap-drop ALL`, pid/mem limits. The subprocess runner does
**not** enforce network isolation or capability dropping at the OS level.
Mitigation:

- the only executable ever invoked is a **fake shim we control**, so there is no
  real `convert`/curl/etc. to abuse;
- work happens in a throwaway temp dir;
- a hard timeout bounds runtime;
- the demonstrated payload only writes a local marker.

This keeps the exercise safe for a local, single-user research machine (the
threat model actor is the owner/FYP triggering the vuln on purpose, TDD §35). If
stronger isolation is ever needed, the container sandbox can be reintroduced
behind the same runner contract.

## Runner contract (to be implemented in MCP05)

```
request:  { "argv": ["convert", "a.txt", "out.pdf"] }        # secure (no shell)
          { "shell": "convert a.txt out.pdf" }               # vulnerable
response: { "exit_code": 0, "stdout": "...", "stderr": "...",
            "marker_present": false }
```
