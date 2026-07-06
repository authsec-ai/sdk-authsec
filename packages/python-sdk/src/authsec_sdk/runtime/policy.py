"""Tool→scope policy primitives.

The authoritative tool→scope mapping lives in AuthSec's Scope Matrix UI. When
``resource_server_id`` is set in :class:`Config`, the SDK fetches this mapping
from AuthSec at startup and refreshes it periodically. Developers do not need
to maintain tool→scope mappings in code.

A :class:`ToolScopeMap` can also be set directly via ``Config.tool_scopes`` as a
local defense-in-depth fallback.

TypeScript parity: mirrors runtime/policy.ts — adds ``ToolPolicyOutcome`` Literal,
``LookupResult`` dataclass (TS ``ToolPolicyResult`` interface), and
``tool_scope_map_from_record()`` helper.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Literal, Optional


# ── Type aliases ──────────────────────────────────────────────────────────────

# Simple mapping used by Config.tool_scopes and as the internal cache format.
# tool name → list of required scopes (empty list = public tool).
ToolScopeMap = dict[str, list[str]]

# Three-state outcome string — mirrors TS ToolPolicyOutcome.
ToolPolicyOutcome = Literal["absent", "public", "scoped"]


# ── Legacy enum (kept for backwards compatibility) ─────────────────────────

class ToolPolicyResult(enum.Enum):
    """Three-state outcome of :func:`lookup_tool`.

    .. deprecated::
        Use :class:`LookupResult` (returned by :func:`lookup_tool`) and the
        ``ToolPolicyOutcome`` type alias instead. This enum is kept for
        backwards compatibility only.
    """

    ABSENT = "absent"
    PUBLIC = "public"
    SCOPED = "scoped"


# ── Rich lookup result (TypeScript ToolPolicyResult interface parity) ─────────

@dataclass
class LookupResult:
    """Result of resolving a tool against the policy map.

    TypeScript parity: mirrors the ``ToolPolicyResult`` interface in
    ``runtime/policy.ts``.

    Attributes
    ----------
    outcome:
        ``"absent"`` — tool not in map (deny unless mode=open).
        ``"public"`` — empty required_any list, allow any valid token.
        ``"scoped"`` — at least one scope in ``required_any`` is needed.
    required_any:
        Scopes required (at least one must be granted). Empty for ABSENT/PUBLIC.
    denied:
        Non-empty when the policy itself signals a hard deny independent of
        the principal's scopes — e.g. ``"policy_incomplete"`` when the
        scope matrix backend hasn't finished publishing.
    """

    outcome: ToolPolicyOutcome
    required_any: list[str] = field(default_factory=list)
    denied: Optional[str] = None


# ── Core lookup function ───────────────────────────────────────────────────────

def lookup_tool(
    tool_map: Optional[ToolScopeMap],
    tool_name: str,
) -> LookupResult:
    """Look up a tool in the policy map.

    Returns a :class:`LookupResult` with the outcome and required scopes.
    Callers combine this with the effective policy mode to decide whether to
    allow an absent tool.

    TypeScript parity: mirrors ``lookupTool()`` in ``runtime/policy.ts``.
    The old tuple-returning signature is no longer supported; update call sites
    to use ``result.outcome`` / ``result.required_any`` instead of unpacking.
    """
    if tool_map is None:
        return LookupResult(outcome="absent", required_any=[])
    name = (tool_name or "").strip()
    if name not in tool_map:
        return LookupResult(outcome="absent", required_any=[])
    scopes = tool_map[name]
    if not scopes:
        return LookupResult(outcome="public", required_any=[])
    return LookupResult(outcome="scoped", required_any=list(scopes))


def required_scopes(tool_map: Optional[ToolScopeMap], tool_name: str) -> list[str]:
    """Return the scopes required for a tool, or [] if no mapping.

    .. deprecated:: 4.3.0
       Prefer :func:`lookup_tool` for deny-by-default semantics.
    """
    if tool_map is None:
        return []
    return list(tool_map.get(tool_name.strip(), []))


def has_any_required(
    tool_map: Optional[ToolScopeMap],
    tool_name: str,
    granted: set[str],
) -> bool:
    """True iff a principal with ``granted`` scopes satisfies a tool's
    scope requirement. No requirement → True."""
    req = required_scopes(tool_map, tool_name)
    if not req:
        return True
    return any(scope in granted for scope in req)


def tool_scope_map_from_record(
    record: Optional[dict[str, list[str]]],
) -> Optional[ToolScopeMap]:
    """Build a :class:`ToolScopeMap` from a plain ``{tool: [scopes]}`` dict.

    Empty scope list → public tool (no scope needed for any valid token).
    Returns ``None`` when ``record`` is ``None`` or empty.

    TypeScript parity: mirrors ``toolScopeMapFromRecord()`` in
    ``runtime/policy.ts``.
    """
    if not record:
        return None
    result: ToolScopeMap = {}
    for name, scopes in record.items():
        result[name] = list(scopes or [])
    return result


# Camel-case alias for TypeScript parity
toolScopeMapFromRecord = tool_scope_map_from_record
