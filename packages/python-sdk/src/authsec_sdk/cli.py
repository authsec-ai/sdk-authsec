"""
AuthSec CLI — interactive setup for .authsec.json configuration.

Usage:
    authsec init          Interactive URL + client_id setup
    authsec config show   Display current saved configuration
"""

import json
import os
import sys

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
    else:
        print(f"Unknown command: {' '.join(args)}")
        print(__doc__.strip())
        sys.exit(1)


if __name__ == "__main__":
    main()
