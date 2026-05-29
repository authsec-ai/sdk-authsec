"""Tool→scope policy primitives.

The authoritative tool→scope mapping lives in AuthSec's Scope Matrix UI. When
``resource_server_id`` is set in :class:`Config`, the SDK fetches this mapping
from AuthSec at startup and refreshes it periodically. Developers do not need
to maintain tool→scope mappings in code.

A :class:`ToolScopeMap` can also be set directly via ``Config.tool_scopes`` as a
local defense-in-depth fallback.
"""

from __future__ import annotations

import enum
from typing import Optional


# Type alias for clarity. Use a plain dict for ergonomics; the LookupTool helper
# enforces the deny-by-default semantics.
ToolScopeMap = dict[str, list[str]]


class ToolPolicyResult(enum.Enum):
    """Three-state outcome of :func:`lookup_tool`."""

    ABSENT = "absent"
    """Tool has no entry in the map.
    When a non-OPEN policy mode is active, absent tools are denied."""

    PUBLIC = "public"
    """Tool has an explicit empty-list entry.
    Allowed for any valid authenticated token, regardless of scopes."""

    SCOPED = "scoped"
    """Tool requires at least one specific scope."""


def lookup_tool(
    tool_map: Optional[ToolScopeMap], tool_name: str
) -> tuple[ToolPolicyResult, list[str]]:
    """Look up a tool in the policy map.

    Returns a (result, required_scopes) pair. Prefer this over
    :func:`required_scopes` when deny-by-default semantics are needed.
    """
    if tool_map is None:
        return ToolPolicyResult.ABSENT, []
    name = tool_name.strip()
    if name not in tool_map:
        return ToolPolicyResult.ABSENT, []
    scopes = tool_map[name]
    if not scopes:
        return ToolPolicyResult.PUBLIC, []
    return ToolPolicyResult.SCOPED, list(scopes)


def required_scopes(tool_map: Optional[ToolScopeMap], tool_name: str) -> list[str]:
    """Return the scopes required for a tool, or [] if no mapping.

    .. deprecated:: 4.3.0
       Prefer :func:`lookup_tool` for deny-by-default semantics.
    """
    if tool_map is None:
        return []
    return list(tool_map.get(tool_name.strip(), []))


def has_any_required(
    tool_map: Optional[ToolScopeMap], tool_name: str, granted: set[str]
) -> bool:
    """True iff a principal with ``granted`` scopes satisfies a tool's
    scope requirement. No requirement → True."""
    req = required_scopes(tool_map, tool_name)
    if not req:
        return True
    return any(scope in granted for scope in req)
