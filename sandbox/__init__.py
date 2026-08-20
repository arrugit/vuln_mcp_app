"""Sandbox plane package (MCP05 execution).

Docker-free design (D-08): the sandbox is a constrained in-process subprocess
runner, not a container. See ``sandbox/README.md`` for the controls and the
explicit trade-off vs. the old container sandbox.
"""
