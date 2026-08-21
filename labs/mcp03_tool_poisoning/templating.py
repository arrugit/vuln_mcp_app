"""A tiny ``{{ dotted.key }}`` template renderer for help articles.

This is deliberately simple and *not itself* the vulnerability — it faithfully
resolves placeholders against whatever context it is given. The MCP03 flaw is in
*what context the caller passes in* (the vulnerable ``docs.fetch`` passes the
full app config, including the credential; the secure one passes an allow-listed
subset). Keeping the renderer neutral mirrors real code, where the templating
library is fine but the surrounding wiring is over-permissive.
"""
from __future__ import annotations

import re
from typing import Any, Dict

# Matches {{ a.b.c }} with optional surrounding whitespace.
_PLACEHOLDER = re.compile(r"\{\{\s*([\w.]+)\s*\}\}")


def _resolve(path: str, context: Dict[str, Any]) -> Any:
    """Resolve a dotted path (``config.api_key``) against nested dict context."""
    node: Any = context
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def render(body: str, context: Dict[str, Any]) -> str:
    """Return ``body`` with every ``{{ path }}`` replaced by its resolved value.

    Unresolvable placeholders are left as the literal ``{{ path }}`` so a missing
    value is visible rather than silently blanked — this is why the secure
    renderer (narrow context) simply leaves ``{{ config.api_key }}`` untouched.
    """

    def sub(match: "re.Match[str]") -> str:
        value = _resolve(match.group(1), context)
        return match.group(0) if value is None else str(value)

    return _PLACEHOLDER.sub(sub, body)
