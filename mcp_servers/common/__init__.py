"""Shared, always-safe MCP machinery (registry + legit tools)."""
from .registry import Tool, ToolRegistry, ToolResult, build_baseline_registry

__all__ = ["Tool", "ToolRegistry", "ToolResult", "build_baseline_registry"]
