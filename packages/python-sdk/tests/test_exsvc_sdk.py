"""Tests for the External Service SDK (exsvc_sdk)."""

import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from authsec_sdk.exsvc_sdk import (
    ExternalServiceClient,
    ExternalServiceAuthError,
    ExternalServiceError,
    ExternalServiceNotFoundError,
    ServiceCredentials,
    ServiceInfo,
)


SAMPLE_SERVICE = {
    "id": "svc-001",
    "name": "my-llm-api",
    "type": "api",
    "url": "https://api.openai.com",
    "description": "OpenAI API key",
    "tags": ["ai", "llm"],
    "resource_id": "res-001",
    "auth_type": "api_key",
    "agent_accessible": True,
    "created_by": "client-001",
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z",
}

SAMPLE_CREDENTIALS = {
    "service_id": "svc-001",
    "service_name": "my-llm-api",
    "service_type": "api",
    "auth_type": "api_key",
    "url": "https://api.openai.com",
    "credentials": {"api_key": "sk-secret-key-123"},
    "metadata": {},
    "retrieved_at": "2025-01-01T00:00:00Z",
}


def _mock_response(status: int, body: dict):
    """Create a mock aiohttp response context manager."""
    resp = AsyncMock()
    resp.status = status
    resp.read = AsyncMock(return_value=json.dumps(body).encode())
    resp.headers = {"Content-Type": "application/json"}

    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=resp)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


class TestExternalServiceClient(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.delegation = MagicMock()
        self.delegation.ensure_token = AsyncMock(return_value="test-jwt-token")
        self.delegation.auto_refresh = True

        self.client = ExternalServiceClient(
            base_url="https://api.authsec.ai/exsvc",
            delegation_client=self.delegation,
        )

    def test_init_requires_auth(self):
        with self.assertRaises(ExternalServiceError):
            ExternalServiceClient(base_url="https://example.com")

    def test_init_with_static_token(self):
        client = ExternalServiceClient(
            base_url="https://example.com",
            token="static-jwt",
        )
        self.assertEqual(client._static_token, "static-jwt")

    def test_repr(self):
        self.assertIn("delegation", repr(self.client))

    @patch("authsec_sdk.exsvc_sdk.aiohttp.ClientSession")
    async def test_list_services(self, mock_session_cls):
        session = AsyncMock()
        session.request = MagicMock(
            return_value=_mock_response(200, [SAMPLE_SERVICE])
        )
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        services = await self.client.list_services()

        self.assertEqual(len(services), 1)
        self.assertIsInstance(services[0], ServiceInfo)
        self.assertEqual(services[0].name, "my-llm-api")
        self.assertTrue(services[0].agent_accessible)

    @patch("authsec_sdk.exsvc_sdk.aiohttp.ClientSession")
    async def test_get_credentials(self, mock_session_cls):
        session = AsyncMock()
        session.request = MagicMock(
            return_value=_mock_response(200, SAMPLE_CREDENTIALS)
        )
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        creds = await self.client.get_credentials("svc-001")

        self.assertIsInstance(creds, ServiceCredentials)
        self.assertEqual(creds.service_id, "svc-001")
        self.assertEqual(creds.credentials["api_key"], "sk-secret-key-123")

    @patch("authsec_sdk.exsvc_sdk.aiohttp.ClientSession")
    async def test_get_credentials_by_name(self, mock_session_cls):
        # First call: list_services, second call: get_credentials
        session = AsyncMock()
        session.request = MagicMock(
            side_effect=[
                _mock_response(200, [SAMPLE_SERVICE]),
                _mock_response(200, SAMPLE_CREDENTIALS),
            ]
        )
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        creds = await self.client.get_credentials_by_name("my-llm-api")
        self.assertEqual(creds.credentials["api_key"], "sk-secret-key-123")

    @patch("authsec_sdk.exsvc_sdk.aiohttp.ClientSession")
    async def test_404_raises_not_found(self, mock_session_cls):
        session = AsyncMock()
        session.request = MagicMock(
            return_value=_mock_response(404, {"error": "not found"})
        )
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        with self.assertRaises(ExternalServiceNotFoundError):
            await self.client.get_service("nonexistent")

    @patch("authsec_sdk.exsvc_sdk.aiohttp.ClientSession")
    async def test_403_raises_auth_error(self, mock_session_cls):
        session = AsyncMock()
        session.request = MagicMock(
            return_value=_mock_response(403, {"error": "insufficient_scope"})
        )
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        with self.assertRaises(ExternalServiceAuthError):
            await self.client.get_credentials("svc-001")

    def test_service_info_from_dict(self):
        info = ServiceInfo.from_dict(SAMPLE_SERVICE)
        self.assertEqual(info.id, "svc-001")
        self.assertEqual(info.tags, ["ai", "llm"])

    def test_service_credentials_from_dict(self):
        creds = ServiceCredentials.from_dict(SAMPLE_CREDENTIALS)
        self.assertEqual(creds.credentials["api_key"], "sk-secret-key-123")


if __name__ == "__main__":
    unittest.main()
