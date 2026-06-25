# sdk-authsec — Agent notes

Client **SDKs** that add AuthSec auth/authz to MCP servers and AI agents in ~3 lines.
Workspace context: root [`../AGENTS.md`](../AGENTS.md). `CLAUDE.md` points here.

## Layout
- `packages/typescript-sdk` — TS/Node. Build `npm run build` (tsc); runnable examples under `examples/` (e.g. `npm run example:memory`); runtime-denial tests `npm run test:runtime-denials`. Ships a SPIFFE workload proto.
- `packages/python-sdk` — `pyproject.toml` / `setup.py`; `src/`, `tests/`, `examples/`.
- `packages/go-sdk` — Go module (`go.mod`); `client/`, `agent_identity.go`, `manifest_publisher.go`, `firstrun/`, `examples/`.

## What the SDKs wrap (maps to the flows in root AGENTS.md)
- **M2M** — fetch a token via `client_credentials` (secret or private-key JWT) and attach it to MCP calls.
- **XAA / agent identity** — `agent_identity.go` (Go) and equivalents: log a user in, run the token-exchange → ID-JAG → jwt-bearer chain, call the target MCP server.
- **Workload / SPIFFE** — present a JWT-SVID instead of a secret.
- **MCP** — manifest publishing + discovery against the AuthSec AS (`/.well-known/*`, dynamic registration).

## Conventions
- Per-language build/test/lint live in each package's `README.md` + manifest — read those before editing a package.
- Keep the public API tiny and identical in spirit across the 3 languages (the "3 lines" promise). Don't add a capability to one SDK without noting parity in the others.
- Don't add tests unless asked. `git push` is the only approval gate.
- Runnable end-to-end examples per flow are a **deferred** docs phase — `examples/` may be sparse today.
