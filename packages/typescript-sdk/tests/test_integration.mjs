#!/usr/bin/env node
/**
 * Integration tests for AuthSec TypeScript SDK against the local authsec Go service.
 *
 * Requires the authsec service running on localhost:7468.
 * Run with: node tests/test_integration.mjs
 */

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const { configureAuth, getConfig, isConfigured } = require('../dist/config.js');
const { makeAuthRequest, makeServicesRequest, testAuthService, testServices } = require('../dist/http.js');
const { ServiceAccessSDK, ServiceAccessError } = require('../dist/service-access.js');
const { CIBAClient } = require('../dist/ciba.js');

const AUTH_SERVICE_URL = process.env.AUTHSEC_AUTH_SERVICE_URL || 'http://localhost:7468/authsec/sdkmgr/mcp-auth';
const SERVICES_BASE_URL = process.env.AUTHSEC_SERVICES_URL || 'http://localhost:7468/authsec/sdkmgr/services';
const CLIENT_ID = '947f4811-685c-47e7-955b-0cdd43485432-main-client';
const APP_NAME = 'ts-sdk-integration-test';

let passed = 0;
let failed = 0;
const failures = [];

function setup() {
  configureAuth(CLIENT_ID, APP_NAME, {
    authServiceUrl: AUTH_SERVICE_URL,
    servicesBaseUrl: SERVICES_BASE_URL,
    timeout: 10,
    retries: 1,
  });
}

async function test(name, fn) {
  setup();
  try {
    await fn();
    passed++;
    console.log(`  ✅ ${name}`);
  } catch (err) {
    failed++;
    failures.push({ name, error: err.message || err });
    console.log(`  ❌ ${name}: ${err.message || err}`);
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}
function assertEqual(actual, expected, msg) {
  if (actual !== expected) throw new Error(msg || `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}
function assertIn(key, obj, msg) {
  if (!(key in obj)) throw new Error(msg || `Key "${key}" not found in ${JSON.stringify(obj)}`);
}

// ── 1. Configuration Tests ──

await test('configureAuth sets values', () => {
  assert(isConfigured(), 'Should be configured');
  const cfg = getConfig();
  assertEqual(cfg.appName, APP_NAME);
  assert(cfg.clientId.includes('...'), 'Client ID should be masked');
});

await test('configureAuth rejects empty clientId', () => {
  let threw = false;
  try { configureAuth('', 'test'); } catch { threw = true; }
  assert(threw, 'Should throw for empty clientId');
});

await test('configureAuth rejects empty appName', () => {
  let threw = false;
  try { configureAuth('some-id', ''); } catch { threw = true; }
  assert(threw, 'Should throw for empty appName');
});

// ── 2. Health Check Tests ──

await test('testAuthService returns true', async () => {
  const result = await testAuthService();
  assertEqual(result, true);
});

await test('testServices returns true', async () => {
  const result = await testServices();
  assertEqual(result, true);
});

await test('auth health raw response', async () => {
  const result = await makeAuthRequest('health', null, 'GET');
  assertEqual(result.status, 'healthy');
  assertEqual(result.service, 'mcp-auth-service');
});

await test('services health raw response', async () => {
  const result = await makeServicesRequest('health', null, 'GET');
  assertEqual(result.status, 'healthy');
  assertEqual(result.service, 'services-service');
});

// ── 3. MCP Auth Flow Tests ──

await test('start auth session', async () => {
  const result = await makeAuthRequest('start', {
    client_id: CLIENT_ID,
    app_name: APP_NAME,
  });
  assertIn('session_id', result);
  assertIn('authorization_url', result);
  assertIn('instructions', result);
});

await test('tools/list returns OAuth tools', async () => {
  const result = await makeAuthRequest('tools/list', {
    client_id: CLIENT_ID,
    app_name: APP_NAME,
    user_tools: [],
  });
  assertIn('tools', result);
  const toolNames = result.tools.map(t => t.name);
  assert(toolNames.includes('oauth_start'), 'Should have oauth_start');
  assert(toolNames.includes('oauth_authenticate'), 'Should have oauth_authenticate');
  assert(toolNames.includes('oauth_status'), 'Should have oauth_status');
  assert(result.tools.length >= 5, `Should have >= 5 tools, got ${result.tools.length}`);
});

await test('sessions/status returns count', async () => {
  const result = await makeAuthRequest('sessions/status', null, 'GET');
  assertIn('active_authenticated_sessions', result);
});

await test('protect-tool denied without session', async () => {
  const result = await makeAuthRequest('protect-tool', {
    session_id: 'nonexistent-session',
    tool_name: 'test_tool',
    client_id: CLIENT_ID,
    app_name: APP_NAME,
  });
  assertEqual(result.allowed, false);
});

await test('cleanup-sessions works', async () => {
  const result = await makeAuthRequest('cleanup-sessions', {
    client_id: CLIENT_ID,
    app_name: APP_NAME,
  });
  assertIn('sessions_cleaned', result);
});

await test('logout session', async () => {
  // Start a session first
  const start = await makeAuthRequest('start', {
    client_id: CLIENT_ID,
    app_name: APP_NAME,
  });
  const sessionId = start.session_id;

  // Logout via query param (POST with session_id in URL)
  const resp = await fetch(`${AUTH_SERVICE_URL}/logout?session_id=${sessionId}`, {
    method: 'POST',
  });
  const result = await resp.json();
  assertEqual(result.status, 'logged_out');
});

// ── 4. Services API Tests ──

await test('credentials requires valid session', async () => {
  const result = await makeServicesRequest('credentials', {
    session_id: 'nonexistent',
    service_name: 'github',
  });
  assertIn('error', result);
});

await test('user-details requires valid session', async () => {
  const result = await makeServicesRequest('user-details', {
    session_id: 'nonexistent',
    service_name: 'github',
  });
  assertIn('error', result);
});

// ── 5. ServiceAccessSDK Tests ──

await test('ServiceAccessSDK init with object session', () => {
  const sdk = new ServiceAccessSDK({ session_id: 'test-123' });
  assertEqual(sdk.sessionId, 'test-123');
});

await test('ServiceAccessSDK rejects bad session', () => {
  let threw = false;
  try { new ServiceAccessSDK({ no_session: true }); } catch { threw = true; }
  assert(threw, 'Should throw for missing session_id');
});

await test('ServiceAccessSDK health check', async () => {
  const sdk = new ServiceAccessSDK({ session_id: 'test-123' });
  const result = await sdk.healthCheck();
  assertEqual(result.status, 'healthy');
});

await test('ServiceAccessSDK getCredentials fails without session', async () => {
  const sdk = new ServiceAccessSDK({ session_id: 'no-such-session' });
  let threw = false;
  try { await sdk.getServiceCredentials('github'); } catch { threw = true; }
  assert(threw, 'Should throw ServiceAccessError');
});

// ── 6. CIBAClient Tests ──

await test('CIBAClient init with defaults', () => {
  const client = new CIBAClient();
  assertEqual(client.baseUrl, 'https://dev.api.authsec.dev');
});

await test('CIBAClient init with custom baseUrl', () => {
  const client = new CIBAClient({ baseUrl: 'http://localhost:7468' });
  assertEqual(client.baseUrl, 'http://localhost:7468');
});

await test('CIBAClient init with clientId', () => {
  const client = new CIBAClient({ clientId: 'test-client-id' });
  assertEqual(client.clientId, 'test-client-id');
});

// ── 7. Backward Compatibility ──

await test('old /sdkmgr/mcp-auth/health path works', async () => {
  const resp = await fetch('http://localhost:7468/sdkmgr/mcp-auth/health');
  const data = await resp.json();
  assertEqual(data.status, 'healthy');
});

await test('old /sdkmgr/services/health path works', async () => {
  const resp = await fetch('http://localhost:7468/sdkmgr/services/health');
  const data = await resp.json();
  assertEqual(data.status, 'healthy');
});

await test('SDK works with old-style URLs', async () => {
  configureAuth(CLIENT_ID, APP_NAME, {
    authServiceUrl: 'http://localhost:7468/sdkmgr/mcp-auth',
    servicesBaseUrl: 'http://localhost:7468/sdkmgr/services',
  });
  const auth = await testAuthService();
  const svc = await testServices();
  assertEqual(auth, true);
  assertEqual(svc, true);
});

// ── 8. E2E Lifecycle ──

await test('full E2E lifecycle', async () => {
  // 1. Health
  assertEqual(await testAuthService(), true);
  assertEqual(await testServices(), true);

  // 2. Start session
  const start = await makeAuthRequest('start', {
    client_id: CLIENT_ID,
    app_name: APP_NAME,
  });
  assertIn('session_id', start);
  const sessionId = start.session_id;

  // 3. List tools with user tool
  const toolsResp = await makeAuthRequest('tools/list', {
    client_id: CLIENT_ID,
    app_name: APP_NAME,
    user_tools: [{
      name: 'test_calculator',
      description: 'A test calculator',
      inputSchema: {
        type: 'object',
        properties: { a: { type: 'number' }, b: { type: 'number' } },
      },
    }],
  });
  const toolNames = toolsResp.tools.map(t => t.name);
  assert(toolNames.includes('oauth_start'), 'Should have oauth_start');
  assert(toolNames.includes('test_calculator'), 'Should have test_calculator');

  // 4. Protect tool (denied - no auth)
  const protect = await makeAuthRequest('protect-tool', {
    session_id: sessionId,
    tool_name: 'test_calculator',
    client_id: CLIENT_ID,
    app_name: APP_NAME,
  });
  assertEqual(protect.allowed, false);

  // 5. Session status
  const status = await makeAuthRequest(`status/${sessionId}`, null, 'GET');
  assertIn('session_id', status);

  // 6. Cleanup
  const cleanup = await makeAuthRequest('cleanup-sessions', {
    client_id: CLIENT_ID,
    app_name: APP_NAME,
  });
  assertIn('sessions_cleaned', cleanup);

  // 7. Logout
  const logoutResp = await fetch(`${AUTH_SERVICE_URL}/logout?session_id=${sessionId}`, {
    method: 'POST',
  });
  const logout = await logoutResp.json();
  assertEqual(logout.status, 'logged_out');
});

// ── 9. JWT-Authenticated Endpoint Tests ──

const SDKMGR_BASE = AUTH_SERVICE_URL.replace('/mcp-auth', '');
const TENANT_ID = '947f4811-685c-47e7-955b-0cdd43485432';

const { createHmac, randomUUID } = await import('node:crypto');

function makeJWT(secret = 'authsecai', expOffset = 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    tenant_id: TENANT_ID,
    user_id: randomUUID(),
    email_id: 'test@example.com',
    sub: randomUUID(),
    roles: ['admin'],
    scope: ['read', 'write'],
    iss: 'authsec-ai/auth-manager',
    aud: 'authsec-api',
    iat: now,
    nbf: now,
    exp: now + expOffset,
    token_type: 'default',
  };
  const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const unsigned = b64url(header) + '.' + b64url(payload);
  const sig = createHmac('sha256', secret).update(unsigned).digest('base64url');
  return unsigned + '.' + sig;
}

await test('dashboard/statistics requires JWT (401 without)', async () => {
  const resp = await fetch(`${SDKMGR_BASE}/dashboard/statistics`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenant_id: TENANT_ID }),
  });
  assertEqual(resp.status, 401);
  const data = await resp.json();
  assertIn('error', data);
});

await test('dashboard/statistics succeeds with valid JWT', async () => {
  const token = makeJWT();
  const resp = await fetch(`${SDKMGR_BASE}/dashboard/statistics`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ tenant_id: TENANT_ID }),
  });
  assertEqual(resp.status, 200);
  const data = await resp.json();
  assertEqual(data.success, true);
  assertIn('statistics', data);
});

await test('dashboard/admin-users succeeds with valid JWT', async () => {
  const token = makeJWT();
  const resp = await fetch(`${SDKMGR_BASE}/dashboard/admin-users`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ tenant_id: TENANT_ID }),
  });
  assertEqual(resp.status, 200);
  const data = await resp.json();
  assertEqual(data.success, true);
  assertIn('admin_users', data);
});

await test('dev-server/status auth passes with JWT (not 401)', async () => {
  const token = makeJWT();
  const resp = await fetch(`${SDKMGR_BASE}/playground/dev-server/status`, {
    headers: { 'Authorization': `Bearer ${token}` },
  });
  assert(resp.status !== 401, `Expected non-401, got ${resp.status}`);
});

await test('expired JWT rejected with 401', async () => {
  const token = makeJWT('authsecai', -3600); // expired 1h ago
  const resp = await fetch(`${SDKMGR_BASE}/dashboard/statistics`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ tenant_id: TENANT_ID }),
  });
  assertEqual(resp.status, 401);
});

await test('wrong-secret JWT rejected with 401', async () => {
  const token = makeJWT('wrong-secret');
  const resp = await fetch(`${SDKMGR_BASE}/dashboard/statistics`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ tenant_id: TENANT_ID }),
  });
  assertEqual(resp.status, 401);
});

// ── Results ──

console.log('\n' + '='.repeat(60));
console.log(`TypeScript SDK Integration Tests: ${passed} passed, ${failed} failed`);
if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  - ${f.name}: ${f.error}`);
  }
}
console.log('='.repeat(60));

process.exit(failed > 0 ? 1 : 0);
