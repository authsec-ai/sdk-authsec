import base64
import json
import sys
import unittest
from pathlib import Path

from aiohttp import web

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import AuthSec_SDK
import authsec_sdk
from authsec_sdk import DelegationClient, DelegationError, DelegationTokenExpired, DelegationTokenNotFound
from authsec_sdk.delegation_sdk import DelegationHTTPResponse


def make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header}.{body}.sig"


class AsyncHttpTestCase(unittest.IsolatedAsyncioTestCase):
    async def start_server(self):
        if not hasattr(self, "app"):
            self.app = web.Application()
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()
        sockets = self.site._server.sockets
        self.base_url = f"http://127.0.0.1:{sockets[0].getsockname()[1]}"

    async def asyncTearDown(self):
        if hasattr(self, "runner"):
            await self.runner.cleanup()


class DelegationCompatibilityTest(unittest.TestCase):
    def test_import_surface_matches_agent_contract(self):
        self.assertEqual(authsec_sdk.__version__, "4.1.0")
        self.assertTrue(hasattr(authsec_sdk, "DelegationClient"))
        self.assertTrue(hasattr(authsec_sdk, "DelegationHTTPResponse"))
        self.assertTrue(hasattr(AuthSec_SDK, "DelegationClient"))
        self.assertTrue(hasattr(AuthSec_SDK, "mcp_tool"))

        client = DelegationClient(
            client_id="agent-client",
            userflow_url="https://example.test/uflow",
        )
        for attr in [
            "pull_token",
            "ensure_token",
            "has_permission",
            "decode_token_claims",
            "spiffe_id",
            "permissions",
            "expires_in_seconds",
            "client_id",
        ]:
            self.assertTrue(hasattr(client, attr), attr)


class DelegationBehaviorTest(AsyncHttpTestCase):
    async def test_pull_token_populates_cached_state_and_helpers(self):
        self.app = web.Application()
        jwt = make_jwt({"tenant_id": "tenant-123", "sub": "agent-1"})

        async def handle_pull(_request):
            return web.json_response(
                {
                    "token": jwt,
                    "spiffe_id": "spiffe://authsec/agent",
                    "permissions": ["users:read", "clients:read"],
                    "expires_at": "2099-01-01T00:00:00Z",
                    "tenant_id": "tenant-123",
                }
            )

        self.app.router.add_get("/sdk/delegation-token", handle_pull)
        await self.start_server()

        client = DelegationClient(client_id="agent-client", userflow_url=self.base_url)
        info = await client.pull_token()

        self.assertEqual(info["spiffe_id"], "spiffe://authsec/agent")
        self.assertEqual(client.spiffe_id, "spiffe://authsec/agent")
        self.assertTrue(client.has_permission("users:read"))
        self.assertTrue(client.has_any_permission("unknown", "clients:read"))
        self.assertTrue(client.has_all_permissions("users:read", "clients:read"))
        self.assertGreater(client.expires_in_seconds, 0)
        self.assertEqual(client.decode_token_claims()["tenant_id"], "tenant-123")
        self.assertEqual(client.get_auth_header()["Authorization"], f"Bearer {jwt}")

    async def test_pull_token_404_raises_not_found(self):
        self.app = web.Application()

        async def handle_pull(_request):
            return web.json_response({"error": "missing"}, status=404)

        self.app.router.add_get("/sdk/delegation-token", handle_pull)
        await self.start_server()

        client = DelegationClient(client_id="agent-client", userflow_url=self.base_url)
        with self.assertRaisesRegex(DelegationTokenNotFound, "missing"):
            await client.pull_token()

    async def test_pull_token_410_raises_expired(self):
        self.app = web.Application()

        async def handle_pull(_request):
            return web.json_response({"error": "expired"}, status=410)

        self.app.router.add_get("/sdk/delegation-token", handle_pull)
        await self.start_server()

        client = DelegationClient(client_id="agent-client", userflow_url=self.base_url)
        with self.assertRaisesRegex(DelegationTokenExpired, "expired"):
            await client.pull_token()

    async def test_request_refreshes_once_after_401(self):
        self.app = web.Application()
        first_jwt = make_jwt({"generation": 1})
        second_jwt = make_jwt({"generation": 2})
        token_calls = 0
        protected_calls = 0

        async def handle_pull(_request):
            nonlocal token_calls
            token_calls += 1
            jwt = first_jwt if token_calls == 1 else second_jwt
            return web.json_response(
                {
                    "token": jwt,
                    "permissions": ["users:read"],
                    "spiffe_id": "spiffe://authsec/agent",
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            )

        async def handle_protected(request):
            nonlocal protected_calls
            protected_calls += 1
            auth_header = request.headers.get("Authorization")
            if auth_header == f"Bearer {first_jwt}":
                return web.json_response({"error": "expired token"}, status=401)
            self.assertEqual(auth_header, f"Bearer {second_jwt}")
            return web.json_response({"ok": True, "calls": protected_calls})

        self.app.router.add_get("/sdk/delegation-token", handle_pull)
        self.app.router.add_get("/protected", handle_protected)
        await self.start_server()

        client = DelegationClient(client_id="agent-client", userflow_url=self.base_url)
        response = await client.request("GET", f"{self.base_url}/protected")

        self.assertIsInstance(response, DelegationHTTPResponse)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.json(), {"ok": True, "calls": 2})
        self.assertEqual(token_calls, 2)
        self.assertEqual(protected_calls, 2)

    async def test_request_json_raises_delegation_error_for_non_json(self):
        self.app = web.Application()
        jwt = make_jwt({"tenant_id": "tenant-123"})

        async def handle_pull(_request):
            return web.json_response(
                {
                    "token": jwt,
                    "permissions": ["users:read"],
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            )

        async def handle_plain(_request):
            return web.Response(text="plain-text", content_type="text/plain")

        self.app.router.add_get("/sdk/delegation-token", handle_pull)
        self.app.router.add_get("/plain", handle_plain)
        await self.start_server()

        client = DelegationClient(client_id="agent-client", userflow_url=self.base_url)
        with self.assertRaisesRegex(DelegationError, "Expected JSON object response"):
            await client.request_json("GET", f"{self.base_url}/plain")

    async def test_request_wraps_network_failures_as_delegation_error(self):
        client = DelegationClient(
            client_id="agent-client",
            userflow_url="http://127.0.0.1:1",
            timeout=1,
        )
        client._token = "cached-token"
        client._expires_at = 4102444800

        with self.assertRaisesRegex(DelegationError, "Network error calling delegated endpoint"):
            await client.request("GET", "http://127.0.0.1:1/protected")


if __name__ == "__main__":
    unittest.main()
