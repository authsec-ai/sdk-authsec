import { DelegationClient } from '../dist/index.js';

const clientId = process.env.AUTHSEC_CLIENT_ID;
const userflowUrl = process.env.AUTHSEC_USERFLOW_URL ?? 'https://prod.api.authsec.ai/uflow';
const targetUrl = process.env.TARGET_URL ?? '';

if (!clientId) {
  console.error('Set AUTHSEC_CLIENT_ID before running this example.');
  process.exit(1);
}

const client = new DelegationClient({
  clientId,
  userflowUrl,
});

const tokenInfo = await client.pullToken();
console.log(
  JSON.stringify(
    {
      clientId: client.clientId,
      spiffeId: client.spiffeId,
      permissions: client.permissions,
      expiresInSeconds: client.expiresInSeconds,
      tokenInfo,
    },
    null,
    2,
  ),
);

if (targetUrl) {
  const response = await client.request('GET', targetUrl);
  console.log(`GET ${targetUrl} -> ${response.status}`);
  console.log(response.text().slice(0, 1000));
}
