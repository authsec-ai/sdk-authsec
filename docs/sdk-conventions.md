# SDK conventions

> Cross-language conventions for the three AuthSec SDK packages.
> Read before adding a new feature to any SDK.

## The "3 lines" promise

Every SDK exposes the AuthSec auth pattern in ≤3 lines at the call site:
```go
client := authsec.NewClient(config)
token := client.GetToken(ctx, resource)
mcpClient.Call(ctx, tool, args, authsec.WithToken(token))
```
Any new capability must preserve this simplicity at the public surface.

## Packages

| Package | Path | Build | Test |
|---|---|---|---|
| Go SDK | `packages/go-sdk/` | `go build ./...` | `go test ./...` |
| TypeScript SDK | `packages/typescript-sdk/` | `npm run build` | `npm run test:runtime-denials` |
| Python SDK | `packages/python-sdk/` | `pip install -e .` | standard pytest |

## What each SDK wraps

| Flow | Go | TypeScript | Python |
|---|---|---|---|
| **M2M** (`client_credentials`) | `client/` — token fetch + attach | `src/` — fetch + attach | `src/` — fetch + attach |
| **XAA / agent identity** | `agent_identity.go` — token exchange → ID-JAG → jwt-bearer chain | `src/agentIdentity.ts` | `src/agent_identity.py` |
| **SPIFFE workload** | SPIFFE JWT-SVID presentation via SPIRE workload API | `examples/spiffe/` | `examples/spiffe/` |
| **MCP manifest** | `manifest_publisher.go` — publish + refresh | TS equivalent | Python equivalent |
| **First-run / setup** | `firstrun/` — register, configure workspace | — | — |

## Parity rule

**Don't add a capability to one SDK without noting parity in the others.**
Open a TODO comment in the other packages if parity isn't immediate.
The three SDKs must tell the same story in their respective languages.

## Flows these SDKs exercise

| Flow | Backend doc |
|---|---|
| M2M | `authsec/docs/flows/m2m.md` |
| XAA / ID-JAG | `authsec/docs/flows/xaa-idjag.md` |
| SPIFFE workload | `authsec/docs/flows/spiffe-workload.md` |
| MCP discovery / DCR | `authsec/docs/flows/mcp-discovery.md` |

Before changing an SDK auth flow, read the corresponding backend doc to understand
the exact token format, error codes, and claim expectations.

## Examples (`packages/<sdk>/examples/`)

Each example demonstrates one flow end-to-end. When writing or fixing an example:
1. State which flow it demonstrates in the file header comment.
2. Use environment variables for all secrets/URLs (never hardcode).
3. Keep it runnable against the live deploy (`app.authsec.ai`) or a local stack.

## Versioning

Versions are in `CHANGELOG.md` per package. The 3 SDKs version independently
(Go: module version in `go.mod`; TS: `package.json`; Python: `pyproject.toml`).
