"""
AuthSec CLI — interactive setup + diagnostic helpers.

Usage:
    authsec init          Interactive URL + client_id setup
    authsec config show   Display current saved configuration
    authsec doctor        Decode and inspect a cached AuthSec access token
                          (looks in ~/.mcp_agent_tokens/*.json by default,
                          or pass a path to a JSON / JWT file).
"""

import base64
import glob
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

CONFIG_FILE = ".authsec.json"

DEFAULTS = {
    "auth_service_url": "https://prod.api.authsec.ai/sdkmgr/mcp-auth",
    "services_base_url": "https://prod.api.authsec.ai/sdkmgr/services",
    "ciba_base_url": "https://prod.api.authsec.ai",
}


def _prompt(message, default=None):
    """Prompt user for input with an optional default."""
    if default:
        raw = input(f"{message} [{default}]: ").strip()
        return raw if raw else default
    while True:
        raw = input(f"{message}: ").strip()
        if raw:
            return raw
        print("  This field is required.")


def _config_path():
    return os.path.join(os.getcwd(), CONFIG_FILE)


def cmd_init():
    """Interactive setup that writes .authsec.json to the current directory."""
    print("AuthSec SDK — interactive setup\n")

    choice = _prompt("Use default AuthSec URLs or custom? (default/custom)", "default")

    if choice.lower().startswith("c"):
        auth_service_url = _prompt("Auth Service URL", DEFAULTS["auth_service_url"])
        services_base_url = _prompt("Services Base URL", DEFAULTS["services_base_url"])
        ciba_base_url = _prompt("CIBA Base URL", DEFAULTS["ciba_base_url"])
    else:
        auth_service_url = DEFAULTS["auth_service_url"]
        services_base_url = DEFAULTS["services_base_url"]
        ciba_base_url = DEFAULTS["ciba_base_url"]

    client_id = _prompt("client_id (required)")

    config = {
        "client_id": client_id,
        "auth_service_url": auth_service_url,
        "services_base_url": services_base_url,
        "ciba_base_url": ciba_base_url,
    }

    path = _config_path()
    with open(path, "w") as f:
        json.dump(config, f, indent=2)

    print(f"\nConfig saved to {path}\n")
    _print_config(config)


def cmd_config_show():
    """Display the current .authsec.json configuration."""
    path = _config_path()
    if not os.path.isfile(path):
        print(f"No config file found at {path}")
        print("Run 'authsec init' to create one.")
        sys.exit(1)

    with open(path) as f:
        config = json.load(f)

    _print_config(config)


def _print_config(config):
    print("Current AuthSec configuration:")
    for key, value in config.items():
        print(f"  {key}: {value}")


def _b64url_decode(seg: str) -> bytes:
    """RFC 7515 base64url, padded to a 4-char boundary."""
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _decode_jwt_unverified(token: str) -> dict:
    """Decode the JWT payload without signature verification.

    This is a *diagnostic* helper — never use for authorization. We're
    showing the user what their cached token claims, not deciding policy.
    """
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (no '.' separator)")
    return json.loads(_b64url_decode(parts[1]).decode("utf-8"))


def _candidate_token_paths(explicit: str | None) -> list[Path]:
    """Resolve token file path(s) to inspect."""
    if explicit:
        return [Path(explicit).expanduser()]
    # Default agent-cache locations on macOS/Linux and Windows.
    home = Path.home()
    candidates: list[Path] = []
    for sub in [".mcp_agent_tokens", ".authsec", ".authsec/tokens"]:
        d = home / sub
        if d.is_dir():
            for f in sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
                candidates.append(f)
    # Windows USERPROFILE — Path.home() should resolve this, but glob anyway.
    if not candidates and os.name == "nt":
        userprofile = os.environ.get("USERPROFILE")
        if userprofile:
            for f in sorted(
                glob.glob(os.path.join(userprofile, ".mcp_agent_tokens", "*.json")),
                key=lambda p: os.path.getmtime(p),
                reverse=True,
            ):
                candidates.append(Path(f))
    return candidates


def _extract_token(content: str | dict) -> str | None:
    """Find a JWT inside a cache JSON or a plain-text token file."""
    if isinstance(content, dict):
        for key in ("token", "access_token", "id_token", "bearer"):
            v = content.get(key)
            if isinstance(v, str) and v.count(".") >= 2:
                return v
        return None
    s = content.strip()
    if s.count(".") >= 2 and not s.startswith("{"):
        return s
    try:
        return _extract_token(json.loads(s))
    except Exception:
        return None


def _fmt_exp(ts: float | int | None) -> str:
    if not ts:
        return "—"
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        delta = dt - now
        if delta.total_seconds() < 0:
            return f"{dt.isoformat()} (EXPIRED {abs(int(delta.total_seconds() // 60))}m ago)"
        return f"{dt.isoformat()} (in {int(delta.total_seconds() // 60)}m)"
    except Exception:
        return str(ts)


def cmd_doctor(args: list[str]) -> None:
    """Decode and pretty-print a cached AuthSec access token's claims.

    Prints client_id, audience, expiry, scopes, and any AuthSec-specific
    ext.* claims (RBAC permissions, workspace, user). No signature
    verification — this is diagnostic only.
    """
    explicit = args[0] if args else None
    paths = _candidate_token_paths(explicit)
    if not paths:
        print("authsec doctor: no token files found.")
        print("  Looked in: ~/.mcp_agent_tokens, ~/.authsec, ~/.authsec/tokens")
        print("  Pass a path explicitly: authsec doctor /path/to/token.json")
        sys.exit(1)

    print(f"authsec doctor — inspecting {len(paths)} token file(s)\n")
    for path in paths:
        print(f"── {path} " + "─" * max(0, 60 - len(str(path))))
        try:
            raw = path.read_text()
        except OSError as exc:
            print(f"  read error: {exc}")
            continue
        try:
            obj: object = json.loads(raw)
        except json.JSONDecodeError:
            obj = raw
        token = _extract_token(obj)
        if not token:
            print("  (no JWT found in file)")
            continue
        try:
            claims = _decode_jwt_unverified(token)
        except Exception as exc:
            print(f"  not a JWT — opaque token? ({exc})")
            continue

        print(f"  client_id : {claims.get('client_id') or claims.get('aud') or '—'}")
        aud = claims.get("aud")
        print(f"  audience  : {aud if not isinstance(aud, list) else ', '.join(aud)}")
        print(f"  subject   : {claims.get('sub', '—')}")
        print(f"  issuer    : {claims.get('iss', '—')}")
        print(f"  expires   : {_fmt_exp(claims.get('exp'))}")
        scp = claims.get("scp") or claims.get("scope")
        if isinstance(scp, str):
            scp = scp.split()
        print(f"  scopes    : {', '.join(scp) if scp else '(none)'}")
        ext = claims.get("ext") or {}
        if isinstance(ext, dict):
            perms = ext.get("permissions")
            if perms:
                print(f"  permissions: {', '.join(perms) if isinstance(perms, list) else perms}")
            ws = ext.get("workspace_id")
            if ws:
                print(f"  workspace : {ws}")
            email = ext.get("email")
            if email:
                print(f"  user      : {email}")
        print()


def main():
    args = sys.argv[1:]

    if not args or args == ["--help"] or args == ["-h"]:
        print(__doc__.strip())
        sys.exit(0)

    command = args[0]

    if command == "init":
        cmd_init()
    elif command == "config" and len(args) > 1 and args[1] == "show":
        cmd_config_show()
    elif command == "doctor":
        cmd_doctor(args[1:])
    else:
        print(f"Unknown command: {' '.join(args)}")
        print(__doc__.strip())
        sys.exit(1)


if __name__ == "__main__":
    main()
