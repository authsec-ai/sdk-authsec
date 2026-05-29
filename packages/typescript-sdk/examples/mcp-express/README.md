# MCP server protected by AuthSec (Express)

A 30-line Express server exposing two MCP tools (`read_note`, `write_note`),
protected by the AuthSec SDK.

## Run

1. **Register an Application** in your AuthSec admin UI. Public Base URL =
   `http://localhost:8080`, Protected Path = `/mcp`.
2. **Copy the env block** from the Application detail page (paste-ready).
3. **Set the env vars** for this shell:

   ```bash
   export AUTHSEC_RESOURCE=http://localhost:8080/mcp
   export AUTHSEC_ISSUER=https://auth.authsec.dev
   export AUTHSEC_JWKS_URI=https://auth.authsec.dev/oauth/jwks
   export AUTHSEC_INTROSPECTION_ENDPOINT=https://auth.authsec.dev/oauth/introspect
   export AUTHSEC_INTROSPECTION_ID=<your application id>
   export AUTHSEC_INTROSPECTION_SECRET=<the one-time secret>
   export AUTHSEC_SCOPE_MATRIX_URL=https://auth.authsec.dev/authsec/resource-servers/<id>/sdk-policy
   export AUTHSEC_MANIFEST_URL=https://auth.authsec.dev/authsec/resource-servers/<id>/sdk-manifest
   ```

4. **Install and start**:

   ```bash
   npm install
   npm start
   ```

## What you should see

- Unauthenticated request — 401 with the WWW-Authenticate header:

  ```bash
  curl -i -X POST http://localhost:8080/mcp \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_note"}}'
  # HTTP/1.1 401 Unauthorized
  # WWW-Authenticate: Bearer realm="...", resource_metadata="..."
  ```

- Protected-resource metadata (RFC 9728) is auto-served:

  ```bash
  curl http://localhost:8080/.well-known/oauth-protected-resource/mcp
  ```

- Authenticated request with a valid token + the right scope — runs the
  tool, returns the JSON-RPC `result` block.

## Files

- `index.ts` — the entire server, ~50 lines.
- `package.json` — installs `@authsec/sdk` from the workspace.
