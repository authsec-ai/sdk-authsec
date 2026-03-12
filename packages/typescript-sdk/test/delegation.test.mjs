import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

import {
  DelegationClient,
  DelegationError,
  DelegationHTTPResponse,
  DelegationTokenExpired,
  DelegationTokenNotFound,
} from '../dist/index.js';

function createJwt(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.sig`;
}

function createServer(routes) {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(Buffer.from(chunk));
    }
    const body = Buffer.concat(chunks).toString('utf-8');
    await routes(req, res, url, body);
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({
        server,
        baseUrl: `http://127.0.0.1:${address.port}`,
      });
    });
  });
}

test('pullToken caches token info and permission helpers work', async () => {
  const jwt = createJwt({ tenant_id: 'tenant-123', sub: 'agent-1' });
  const { server, baseUrl } = await createServer((req, res, url) => {
    assert.equal(req.method, 'GET');
    assert.equal(url.pathname, '/sdk/delegation-token');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        token: jwt,
        spiffe_id: 'spiffe://authsec/agent',
        permissions: ['users:read', 'clients:read'],
        expires_at: '2099-01-01T00:00:00Z',
        client_id: 'agent-client',
        tenant_id: 'tenant-123',
      }),
    );
  });

  try {
    const client = new DelegationClient({
      clientId: 'agent-client',
      userflowUrl: baseUrl,
    });

    const tokenInfo = await client.pullToken();
    assert.equal(tokenInfo.spiffe_id, 'spiffe://authsec/agent');
    assert.equal(client.token, jwt);
    assert.equal(client.spiffeId, 'spiffe://authsec/agent');
    assert.equal(client.hasPermission('users:read'), true);
    assert.equal(client.hasAnyPermission('unknown', 'clients:read'), true);
    assert.equal(client.hasAllPermissions('users:read', 'clients:read'), true);
    assert.equal(client.expiresInSeconds > 0, true);
    assert.deepEqual(client.decodeTokenClaims(), { tenant_id: 'tenant-123', sub: 'agent-1' });
    assert.deepEqual(client.getAuthHeader(), { Authorization: `Bearer ${jwt}` });
  } finally {
    server.close();
  }
});

test('pullToken throws not-found and expired errors', async () => {
  const { server, baseUrl } = await createServer((req, res, url) => {
    const mode = url.searchParams.get('client_id');
    res.writeHead(mode === 'expired' ? 410 : 404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: mode === 'expired' ? 'expired' : 'missing' }));
  });

  try {
    const missingClient = new DelegationClient({
      clientId: 'missing',
      userflowUrl: baseUrl,
    });
    await assert.rejects(
      () => missingClient.pullToken(),
      (error) =>
        error instanceof DelegationTokenNotFound && error.message === 'missing',
    );

    const expiredClient = new DelegationClient({
      clientId: 'expired',
      userflowUrl: baseUrl,
    });
    await assert.rejects(
      () => expiredClient.pullToken(),
      (error) =>
        error instanceof DelegationTokenExpired && error.message === 'expired',
    );
  } finally {
    server.close();
  }
});

test('request retries once after 401 and returns a buffered response', async () => {
  const firstJwt = createJwt({ generation: 1 });
  const secondJwt = createJwt({ generation: 2 });
  let tokenPullCount = 0;
  let protectedCallCount = 0;

  const { server, baseUrl } = await createServer((req, res, url) => {
    if (url.pathname === '/sdk/delegation-token') {
      tokenPullCount += 1;
      const token = tokenPullCount === 1 ? firstJwt : secondJwt;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          token,
          spiffe_id: 'spiffe://authsec/agent',
          permissions: ['users:read'],
          expires_at: '2099-01-01T00:00:00Z',
        }),
      );
      return;
    }

    if (url.pathname === '/protected') {
      protectedCallCount += 1;
      const auth = req.headers.authorization;
      if (auth === `Bearer ${firstJwt}`) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'expired token' }));
        return;
      }

      assert.equal(auth, `Bearer ${secondJwt}`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, calls: protectedCallCount }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  try {
    const client = new DelegationClient({
      clientId: 'agent-client',
      userflowUrl: baseUrl,
    });

    const response = await client.request('GET', `${baseUrl}/protected`);
    assert.equal(tokenPullCount, 2);
    assert.equal(protectedCallCount, 2);
    assert.ok(response instanceof DelegationHTTPResponse);
    assert.equal(response.status, 200);
    assert.deepEqual(response.json(), { ok: true, calls: 2 });

    const jsonResponse = await client.requestJson('GET', `${baseUrl}/protected`);
    assert.deepEqual(jsonResponse, { ok: true, calls: 3 });
  } finally {
    server.close();
  }
});

test('requestJson raises DelegationError for non-JSON bodies', async () => {
  const jwt = createJwt({ tenant_id: 'tenant-123' });

  const { server, baseUrl } = await createServer((req, res, url) => {
    if (url.pathname === '/sdk/delegation-token') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          token: jwt,
          permissions: ['users:read'],
          expires_at: '2099-01-01T00:00:00Z',
        }),
      );
      return;
    }

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('plain text');
  });

  try {
    const client = new DelegationClient({
      clientId: 'agent-client',
      userflowUrl: baseUrl,
    });

    await assert.rejects(
      () => client.requestJson('GET', `${baseUrl}/plain`),
      (error) => error instanceof DelegationError && /Expected JSON response/.test(error.message),
    );
  } finally {
    server.close();
  }
});

test('network failures are wrapped as DelegationError', async () => {
  const client = new DelegationClient({
    clientId: 'agent-client',
    userflowUrl: 'http://127.0.0.1:1',
    timeoutMs: 200,
  });

  await assert.rejects(
    () => client.pullToken(),
    (error) =>
      error instanceof DelegationError &&
      /Network error pulling delegation token/.test(error.message),
  );
});
