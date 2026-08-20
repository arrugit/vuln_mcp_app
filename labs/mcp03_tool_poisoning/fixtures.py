"""Synthetic fixtures for the MCP03 Tool Poisoning lab.

Contents
--------
* ``DOCS`` — a tiny synthetic document corpus that ``docs.fetch`` serves. The
  ``"welcome"`` document is the one named in the exact exploit call
  (``docs.fetch {"doc_id": "welcome"}``, TDD §15). None of these documents
  contain a secret — a clean fetch returns ONLY the requested document.
* ``DEMO_SECRET_A`` — the synthetic secret value used as the intended leak proof
  in later phases. It lives OUTSIDE the document corpus on purpose: a correct,
  non-poisoned ``docs.fetch`` has no reason to ever touch it. In Phase A nothing
  reads it; the poisoned handler added in Phase B is what (intentionally) will.

Everything here is fake (SEC-002). Phase A wires the clean/trusted path only.
"""
from __future__ import annotations

# --- Synthetic document corpus served by docs.fetch -----------------------
# Keyed by doc_id. Body text is inert, demonstration-only content.
DOCS: dict[str, dict[str, str]] = {
    "welcome": {
        "title": "Welcome",
        "body": (
            "Welcome to the synthetic docs service used by the MCP security "
            "lab. This document is safe, public, and contains no secrets."
        ),
    },
    "getting-started": {
        "title": "Getting Started",
        "body": (
            "Synthetic getting-started guide. Call docs.fetch with a doc_id to "
            "retrieve a document. Nothing here is sensitive."
        ),
    },
    "faq": {
        "title": "FAQ",
        "body": "Synthetic frequently-asked-questions content for the demo lab.",
    },
}

# --- Synthetic secret (leak target for later phases) ----------------------
# NOTE: this is deliberately NOT part of DOCS. A trusted docs.fetch never
# references it. It is defined here so the Phase B poisoned handler and the
# ground-truth write-up have a single, synthetic source of truth (SEC-002).
DEMO_SECRET_A = "DEMO_SECRET_A"


def get_document(doc_id: str) -> dict | None:
    """Return a synthetic document by id, or ``None`` if unknown.

    This is the clean lookup used by the trusted docs.fetch handler. It reads
    ONLY the document corpus — never the secret (that separation is the whole
    point of the lab).
    """
    return DOCS.get(doc_id)
