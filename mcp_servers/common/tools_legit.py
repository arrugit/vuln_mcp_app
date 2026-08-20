"""Legit, always-safe control tools (TDD §13).

``notes.search`` and ``notes.summarize`` operate on a tiny synthetic notes
corpus. They are deliberately boring and deterministic: no instructions in their
metadata, no command execution, no secret access. They exist so the MCP surface
looks realistic and so the FYP has benign tools to contrast against the (later)
lab tools. These tools are SAFE IN EVERY MODE.
"""
from __future__ import annotations

from typing import Any, Dict

from .registry import Tool, ToolRegistry

# A small synthetic corpus. Entirely fake content (SEC-002); no secrets here.
_SYNTHETIC_NOTES: Dict[str, Dict[str, str]] = {
    "note-1": {
        "title": "Welcome",
        "body": "This is a synthetic note used by the MCP security lab.",
    },
    "note-2": {
        "title": "Roadmap",
        "body": "Synthetic roadmap content for demonstration only.",
    },
    "note-3": {
        "title": "Meeting",
        "body": "Synthetic meeting notes; nothing sensitive is stored here.",
    },
}


def _notes_search(args: Dict[str, Any]) -> Dict[str, Any]:
    """Return deterministic keyword matches over the synthetic corpus."""
    query = str(args.get("query", "")).strip().lower()
    matches = []
    for note_id, note in _SYNTHETIC_NOTES.items():
        haystack = f"{note['title']} {note['body']}".lower()
        if query and query in haystack:
            matches.append({"note_id": note_id, "title": note["title"]})
    return {"query": query, "matches": matches}


def _notes_summarize(args: Dict[str, Any]) -> Dict[str, Any]:
    """Return a short deterministic summary of one synthetic note."""
    note_id = str(args.get("note_id", ""))
    note = _SYNTHETIC_NOTES.get(note_id)
    if note is None:
        return {"note_id": note_id, "summary": None, "found": False}
    # Deterministic "summary": first eight words of the body.
    words = note["body"].split()
    summary = " ".join(words[:8])
    return {"note_id": note_id, "summary": summary, "found": True}


def register_legit_tools(registry: ToolRegistry) -> None:
    """Register the always-safe control tools onto a registry."""
    registry.register(
        Tool(
            name="notes.search",
            description="Search the local synthetic notes corpus by keyword.",
            input_schema={
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
            output_schema={
                "type": "object",
                "properties": {"matches": {"type": "array"}},
            },
            handler=_notes_search,
            risk="none",
        )
    )
    registry.register(
        Tool(
            name="notes.summarize",
            description="Return a short deterministic summary of a synthetic note.",
            input_schema={
                "type": "object",
                "properties": {"note_id": {"type": "string"}},
                "required": ["note_id"],
            },
            output_schema={
                "type": "object",
                "properties": {"summary": {"type": "string"}},
            },
            handler=_notes_summarize,
            risk="none",
        )
    )
