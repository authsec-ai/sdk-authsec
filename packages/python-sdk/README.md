# AuthSec Python SDK

Python SDK for AuthSec MCP authentication, RBAC, service access, CIBA, and SPIFFE integrations.

## Install (local)

```bash
pip install -e .
```

## Local MCP Demo

The package includes a real localhost demo server at `examples/local_authsec_demo_server.py`.

1. Copy the env file and set a real `AUTHSEC_CLIENT_ID` from the AuthSec UI.
2. Keep the default local backend URLs unless you need a different backend.
3. Run:

```bash
cd packages/python-sdk
set -a
source examples/local_authsec_demo.env.example
set +a
python examples/local_authsec_demo_server.py
```

The server listens on `http://127.0.0.1:3006` by default and exposes OAuth tools before login plus protected demo tools after the browser flow completes.

## Package layout

- `src/authsec_sdk`: importable Python package
- `pyproject.toml`: package metadata and dependencies
- `MANIFEST.in`: sdist include rules
