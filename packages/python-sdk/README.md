# AuthSec Python SDK

Python SDK for AuthSec MCP authentication, RBAC, service access, CIBA, delegation, and SPIFFE integrations.

## Install

From PyPI:

```bash
pip install authsec-sdk
```

For local SDK development:

```bash
cd packages/python-sdk
pip install -e ".[dev]"
```

## Recommended Setup Flow

The default user flow is:

```bash
pip install authsec-sdk
authsec init
```

`authsec init` writes `.authsec.json` in the current working directory. If you choose the default setup path, it writes these prod endpoints:

- `https://prod.api.authsec.ai/sdkmgr/mcp-auth`
- `https://prod.api.authsec.ai/sdkmgr/services`
- `https://prod.api.authsec.ai`

Use `authsec config show` to verify the saved configuration.

If you need localhost, staging, or self-hosted AuthSec, choose the custom path in `authsec init` or set explicit environment overrides.

## Team Knowledge Base Flow

The intended acceptance flow matches the protected Team Knowledge Base example:

1. `pip install authsec-sdk`
2. `authsec init`
3. Run your protected MCP server
4. Confirm startup logs show the prod AuthSec endpoints by default

When the app name is `Team Knowledge Base (Protected)`, the expected startup output is:

```text
Auth configured: Team Knowledge Base (Protected) with client_id: 921c2209...
Auth service URL: https://prod.api.authsec.ai/sdkmgr/mcp-auth
Services URL: https://prod.api.authsec.ai/sdkmgr/services
Starting Team Knowledge Base (Protected) MCP Server on 0.0.0.0:3005
Authentication via: https://prod.api.authsec.ai/sdkmgr/mcp-auth
Services via: https://prod.api.authsec.ai/sdkmgr/services
SPIRE Workload Identity: DISABLED
```

## Example Server

This package includes a Python MCP demo at `examples/local_authsec_demo_server.py`.

Run it like this:

```bash
cd packages/python-sdk
authsec init
set -a
source examples/local_authsec_demo.env.example
set +a
python examples/local_authsec_demo_server.py
```

By default, the example relies on `.authsec.json` created by `authsec init`. Only set `AUTHSEC_AUTH_SERVICE_URL` or `AUTHSEC_SERVICES_URL` if you intentionally want to override the prod defaults.

## Testing

Install the dev extras and run tests:

```bash
cd packages/python-sdk
pip install -e ".[dev]"
pytest tests/test_config_flow.py
```

The existing integration tests that point at localhost remain explicit local-service tests; they are not the default user path.

## Maintainer Release Flow

Build and verify locally:

```bash
cd packages/python-sdk
python -m build
python -m twine check dist/*
```

Smoke test the built artifact in a fresh virtualenv:

```bash
python -m venv /tmp/authsec-sdk-smoke
source /tmp/authsec-sdk-smoke/bin/activate
pip install /absolute/path/to/packages/python-sdk/dist/authsec_sdk-<version>-py3-none-any.whl
authsec init
```

Publish with token-based Twine auth supplied via environment variables or `.pypirc`, then verify in a fresh virtualenv with:

```bash
pip install authsec-sdk
authsec init
```
