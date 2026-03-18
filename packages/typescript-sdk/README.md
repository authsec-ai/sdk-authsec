# AuthSec TypeScript SDK (`@authsec/sdk`)

TypeScript runtime for exposing MCP tools behind AuthSec OAuth and RBAC.

## Local Memory Wrapper Smoke Test

This package includes a real MCP wrapper example at [`examples/memory-authsec-wrapper.mjs`](examples/memory-authsec-wrapper.mjs). It runs against the local SDK build in `dist/` and proxies the upstream memory server over stdio.

### 1. Install and build the local SDK

```bash
cd packages/typescript-sdk
npm install
npm run build
```

### 2. Create the example env file

```bash
cd packages/typescript-sdk
cp examples/memory-authsec-wrapper.env.example examples/memory-authsec-wrapper.env
```

Update `examples/memory-authsec-wrapper.env` with a real `AUTHSEC_CLIENT_ID`. The defaults in the example file already target the local AuthSec stack:

- `http://localhost:7468/authsec/sdkmgr/mcp-auth`
- `http://localhost:7468/authsec/sdkmgr/services`

Override them only if you need a different backend.

### 3. Run the local wrapper

```bash
cd packages/typescript-sdk
set -a
source examples/memory-authsec-wrapper.env
set +a
npm run example:memory:local
```

`example:memory:local` rebuilds the SDK and then starts the wrapper from the local repo build in `dist/`. The raw runtime entrypoint remains available as `npm run example:memory` if you already exported the environment yourself.

Expected startup output includes:

- effective `appName`
- effective `host` and `port`
- auth and services URLs, marked as `sdk default` or `env override`
- upstream memory server command

### 4. Basic server check

With the server running:

```bash
curl http://127.0.0.1:3005/
```

Expect JSON with:

- `status: "running"`
- `protocol: "mcp-with-oauth"`
- the effective auth and services URLs

### 5. MCP Inspector flow

Open MCP Inspector against the local HTTP endpoint:

```bash
npx @modelcontextprotocol/inspector http://127.0.0.1:3005
```

Manual smoke-test sequence:

1. Call `initialize`.
2. Call `tools/list` before login and confirm the OAuth tools are present.
3. Run `oauth_start` and finish the browser authentication flow.
4. Finish the browser login flow through the local AuthSec UI.
5. Continue with `oauth_status`.
6. Call `tools/list` again and confirm wrapped memory tools are now available.
7. Execute at least one wrapped memory tool successfully.

### 6. Failure-path check

The wrapper should fail fast if `AUTHSEC_CLIENT_ID` is missing:

```bash
cd packages/typescript-sdk
npm run example:memory:local
```

Expected error:

```text
Set AUTHSEC_CLIENT_ID before running
```

## Environment Variables

Required:

- `AUTHSEC_CLIENT_ID`

Common local settings:

- `AUTHSEC_APP_NAME` default: `authsec-memory-wrapper-local`
- `HOST` default: `127.0.0.1`
- `PORT` default: `3005`

Optional backend overrides:

- `AUTHSEC_AUTH_SERVICE_URL`
- `AUTHSEC_SERVICES_URL`

Optional wrapper settings:

- `AUTHSEC_TOOL_ROLES_JSON`
- `MEMORY_FILE_PATH`
- `MEMORY_SERVER_COMMAND`
- `MEMORY_SERVER_ARGS_JSON`

## Package Scripts

- `npm run build` builds the local SDK into `dist/`
- `npm run example:memory` runs the wrapper directly
- `npm run example:memory:local` rebuilds and then runs the wrapper for local smoke testing
