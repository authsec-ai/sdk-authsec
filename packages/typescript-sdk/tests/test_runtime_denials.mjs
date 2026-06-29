#!/usr/bin/env node

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const http = require('node:http');
const { mountMCP } = require('../dist/runtime/server.js');
const { defaultConfig } = require('../dist/runtime/config.js');

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function makeResponseRecorder() {
  return {
    code: 0,
    headers: {},
    payload: undefined,
    status(code) {
      this.code = code;
      return this;
    },
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
      return this;
    },
    json(payload) {
      this.payload = payload;
      return this;
    },
    send(payload) {
      this.payload = payload;
      return this;
    },
  };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function withInactiveIntrospection(fn) {
  const introspection = http.createServer((_req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ active: false }));
  });

  try {
    const port = await listen(introspection);
    await fn(`http://127.0.0.1:${port}/introspect`);
  } finally {
    introspection.close();
  }
}

async function buildProtectedHandler(introspectionUrl) {
  const cfg = defaultConfig();
  Object.assign(cfg, {
    issuer: 'http://auth.example.test',
    authorizationServer: 'http://auth.example.test',
    introspectionUrl,
    introspectionClientId: 'rs',
    introspectionClientSecret: 'secret',
    resourceUri: 'https://mcp.example.test/mcp',
    resourceName: 'Example MCP',
    toolScopes: { slugify: ['demo:write'] },
    policyMode: 'local_only',
    validationMode: 'introspection_only',
  });

  let protectedHandler;
  const app = {
    get() {},
    use(pathOrHandler, maybeHandler) {
      protectedHandler = typeof pathOrHandler === 'function' ? pathOrHandler : maybeHandler;
    },
  };

  await mountMCP(app, { config: cfg, path: '/mcp' });
  return protectedHandler;
}

function toolsCallRequest(headers = {}) {
  return {
    method: 'POST',
    headers,
    body: {
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: {
        name: 'slugify',
        arguments: { text: 'Aman Kumar' },
      },
    },
  };
}

function initializeRequest(headers = {}) {
  return {
    method: 'POST',
    headers,
    body: {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '0.0.0' },
      },
    },
  };
}

function toolsListRequest(headers = {}) {
  return {
    method: 'POST',
    headers,
    body: {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/list',
      params: {},
    },
  };
}

await withInactiveIntrospection(async (introspectionUrl) => {
  const protectedHandler = await buildProtectedHandler(introspectionUrl);

  const initRes = makeResponseRecorder();
  let initNextCalled = false;
  await protectedHandler(
    initializeRequest({ authorization: 'Bearer revoked-token' }),
    initRes,
    () => {
      initNextCalled = true;
    },
  );
  assert(initNextCalled, 'expected revoked initialize to pass through to MCP handler');
  assert(initRes.code === 0, `expected middleware not to write initialize response, got ${initRes.code}`);

  const revokedRes = makeResponseRecorder();
  await protectedHandler(
    toolsCallRequest({ authorization: 'Bearer revoked-token' }),
    revokedRes,
    () => {
      throw new Error('next should not run for revoked tool call');
    },
  );

  assert(revokedRes.code === 200, `expected revoked tools/call HTTP 200, got ${revokedRes.code}`);
  assert(revokedRes.payload?.result?.isError === true, 'expected MCP tool isError payload');
  assert(
    String(revokedRes.payload.result.content?.[0]?.text).includes(
      'Unauthorized to perform this action',
    ),
    'expected friendly unauthorized message',
  );
  assert(
    revokedRes.payload.result._meta?.authsec?.error === 'invalid_token',
    'expected authsec invalid_token metadata',
  );

  const listRes = makeResponseRecorder();
  await protectedHandler(
    toolsListRequest({ authorization: 'Bearer revoked-token' }),
    listRes,
    () => {
      throw new Error('next should not run for revoked tools/list');
    },
  );

  assert(listRes.code === 200, `expected revoked tools/list HTTP 200, got ${listRes.code}`);
  assert(listRes.payload?.error?.message?.includes('Unauthorized to perform this action'), 'expected JSON-RPC auth error');
  assert(
    listRes.payload?.error?.data?.authsec?.error === 'invalid_token',
    'expected JSON-RPC authsec invalid_token metadata',
  );

  const missingRes = makeResponseRecorder();
  await protectedHandler(toolsCallRequest(), missingRes, () => {
    throw new Error('next should not run for missing bearer');
  });

  assert(missingRes.code === 401, `expected missing bearer HTTP 401, got ${missingRes.code}`);
  assert(missingRes.headers['www-authenticate'], 'expected WWW-Authenticate header');
});

console.log('runtime denial regression ok');
