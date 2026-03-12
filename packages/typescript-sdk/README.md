# AuthSec TypeScript SDK (`@authsec/sdk`)

AuthSec TypeScript SDK covers:

- MCP OAuth + RBAC enforcement
- Trust delegation for AI agents
- Hosted service credential access
- CIBA / passwordless authentication
- SPIFFE workload identity helpers

## Install

Consumer install:

```bash
npm install @authsec/sdk
```

From this repo during development:

```bash
cd packages/typescript-sdk
npm install
npm run build
```

## Core MCP Quick Start

```ts
import {
  mcpTool,
  protectedByAuthSec,
  runMcpServerWithOAuth,
} from '@authsec/sdk';

const ping = mcpTool(
  {
    name: 'ping',
    description: 'Health check',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  async () => [{ type: 'text', text: 'pong' }],
);

const deleteInvoice = protectedByAuthSec(
  {
    toolName: 'delete_invoice',
    permissions: ['tool:delete_invoice'],
    requireAll: true,
    description: 'Delete invoice by id',
    inputSchema: {
      type: 'object',
      properties: {
        invoice_id: { type: 'string' },
        session_id: { type: 'string' },
      },
      required: ['invoice_id'],
    },
  },
  async (args) => [{ type: 'text', text: `Deleted ${args.invoice_id}` }],
);

runMcpServerWithOAuth({
  tools: [ping, deleteInvoice],
  clientId: process.env.AUTHSEC_CLIENT_ID!,
  appName: 'my-ts-mcp',
  host: '127.0.0.1',
  port: 3005,
});
```

## Trust Delegation for Agents

Use trust delegation when an agent should pull a delegated JWT-SVID and expose only the capabilities that delegation allows.

```ts
import { DelegationClient } from '@authsec/sdk';

const client = new DelegationClient({
  clientId: process.env.AUTHSEC_CLIENT_ID!,
  userflowUrl: process.env.AUTHSEC_USERFLOW_URL ?? 'https://prod.api.authsec.ai/uflow',
});

const tokenInfo = await client.pullToken();

if (client.hasPermission('users:read')) {
  const result = await client.requestJson('GET', 'https://api.example.com/users');
  console.log(result);
}
```

Delegation exports:

- `DelegationClient`
- `DelegationError`
- `DelegationTokenExpired`
- `DelegationTokenNotFound`
- `DelegationHTTPResponse`

Delegation client surface:

- constructor options: `clientId`, `userflowUrl`, `autoRefresh`, `refreshBufferSeconds`, `timeoutMs`
- getters: `token`, `permissions`, `spiffeId`, `isExpired`, `expiresInSeconds`
- methods: `pullToken()`, `ensureToken()`, `hasPermission()`, `hasAnyPermission()`, `hasAllPermissions()`, `request()`, `requestJson()`, `getAuthHeader()`, `decodeTokenClaims()`

`request()` returns a buffered `DelegationHTTPResponse`, not a live `fetch` response.

Refresh behavior:

- `ensureToken()` refreshes near-expiry tokens
- downstream `401` triggers one refresh and one retry

Example runner:

```bash
cd packages/typescript-sdk
npm run build
AUTHSEC_CLIENT_ID="YOUR_AGENT_CLIENT_ID" \
AUTHSEC_USERFLOW_URL="https://prod.api.authsec.ai/uflow" \
npm run example:delegation
```

## Existing Example Wrapper

The repo also includes an MCP wrapper example:

- `packages/typescript-sdk/examples/memory-authsec-wrapper.mjs`

Run locally:

```bash
cd packages/typescript-sdk
npm install
npm run build
AUTHSEC_CLIENT_ID="YOUR_CLIENT_ID" node examples/memory-authsec-wrapper.mjs
```

## Other Surfaces

Hosted service access:

```ts
import { ServiceAccessSDK } from '@authsec/sdk';
```

CIBA:

```ts
import { CIBAClient } from '@authsec/sdk';
```

SPIFFE:

```ts
import { QuickStartSVID, WorkloadAPIClient, WorkloadSVID } from '@authsec/sdk';
```

## Environment Variables

MCP SDK runtime:

- `AUTHSEC_AUTH_SERVICE_URL`
- `AUTHSEC_SERVICES_URL`
- `AUTHSEC_TIMEOUT_SECONDS`
- `AUTHSEC_RETRIES`
- `AUTHSEC_TOOLS_LIST_TIMEOUT_SECONDS`

Common app config:

- `AUTHSEC_CLIENT_ID`
- `AUTHSEC_APP_NAME`
- `AUTHSEC_USERFLOW_URL`
- `HOST`
- `PORT`

## Testing

```bash
cd packages/typescript-sdk
npm test
```

This runs the TypeScript build and the trust delegation tests.

## Publishing

```bash
cd /absolute/path/to/sdk-authsec/packages/typescript-sdk
npm install
npm run clean
npm run build
npm pack
npm publish --access public
```
