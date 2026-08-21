"""Minimal local Ollama client (optional live-LLM path, NFR-001).

The core labs are deterministic and never need an LLM. This client powers the
OPTIONAL MCP03 "live" demo where a real local model processes (untrusted)
document content, so the difference between naive prompt concatenation
(vulnerable) and guarded prompting (secure) can be seen against a real model.

It is defensive by design: if ``ENABLE_LOCAL_LLM`` is false, or Ollama is not
reachable, ``available()`` is False and callers fall back gracefully — the lab
still works fully without it.
"""
from __future__ import annotations

from typing import Optional

import httpx

from ..config import get_settings


class OllamaClient:
    def __init__(self) -> None:
        self._settings = get_settings()

    @property
    def model(self) -> str:
        return self._settings.ollama_model

    def available(self) -> bool:
        """True only if the owner enabled the LLM AND Ollama answers quickly."""
        if not self._settings.enable_local_llm:
            return False
        try:
            resp = httpx.get(f"{self._settings.ollama_url}/api/tags", timeout=2.0)
            return resp.status_code == 200
        except Exception:
            return False

    def generate(self, prompt: str, system: Optional[str] = None) -> Optional[str]:
        """Return the model's text for ``prompt`` (with optional ``system``).

        Returns None on any error so callers never crash on an LLM hiccup.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            # Low temperature to make the demo as repeatable as a local LLM allows.
            "options": {"temperature": 0.0},
        }
        if system is not None:
            payload["system"] = system
        try:
            resp = httpx.post(
                f"{self._settings.ollama_url}/api/generate",
                json=payload,
                timeout=60.0,
            )
            resp.raise_for_status()
            return resp.json().get("response", "")
        except Exception:
            return None
