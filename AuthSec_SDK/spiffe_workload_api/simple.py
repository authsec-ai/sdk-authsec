"""
SPIFFE Workload API - Simplified Quick Start

This module provides a drop-in integration helper for services to quickly
fetch and use SVIDs with just 1 line of code.

Example:
    from spiffe_workload_api.simple import QuickStartSVID

    # Initialize (1 line!)
    svid = await QuickStartSVID.initialize(socket_path="/run/spire/sockets/agent.sock")

    # Access SVID data
    print(f"SPIFFE ID: {svid.spiffe_id}")
    print(f"Certificate: {svid.certificate}")
"""

import asyncio
import logging
import os
import ssl
from pathlib import Path
from typing import Optional
from .client import WorkloadAPIClient


class QuickStartSVID:
    """
    Minimal SVID integration helper.

    Provides the simplest possible way to integrate SPIFFE SVIDs into any service.
    Single async call returns fully initialized SVID ready to use with automatic renewal.
    """

    _instance: Optional['QuickStartSVID'] = None
    _lock = asyncio.Lock()

    def __init__(
        self,
        socket_path: str = "tcp://127.0.0.1:4000",
        cert_dir: str = "/tmp/spiffe-certs"
    ):
        self.socket_path = socket_path
        self.cert_dir = Path(cert_dir)
        self.logger = logging.getLogger("spiffe")
        self.client = WorkloadAPIClient(socket_path=socket_path, logger=self.logger)

        # Expose SVID data
        self.spiffe_id: Optional[str] = None
        self.certificate: Optional[str] = None
        self.private_key: Optional[str] = None
        self.trust_bundle: Optional[str] = None

        # Persistent certificate files for mTLS (auto-managed)
        self.cert_file_path: Optional[Path] = None
        self.key_file_path: Optional[Path] = None
        self.ca_file_path: Optional[Path] = None

    @classmethod
    async def initialize(
        cls,
        socket_path: str = "tcp://127.0.0.1:4000"
    ) -> 'QuickStartSVID':
        """
        Initialize and fetch SVID in one call (singleton pattern).

        Usage:
            svid = await QuickStartSVID.initialize(socket_path="/run/spire/sockets/agent.sock")
            print(svid.spiffe_id)

        Args:
            socket_path: Path to agent Workload API (default: TCP localhost:4000)

        Returns:
            QuickStartSVID instance with SVID data populated and automatic renewal enabled

        Raises:
            RuntimeError: If SVID fetch fails
        """
        async with cls._lock:
            if cls._instance is None:
                cls._instance = cls(socket_path=socket_path)
                await cls._instance._fetch()
            return cls._instance

    async def _fetch(self) -> None:
        """Fetch SVID from agent and start streaming for automatic renewal"""
        self.logger.info("Fetching SPIFFE SVID...")

        try:
            # Start streaming - this will fetch initial SVID and keep renewing
            await self.client.start_streaming(on_update=self._on_cert_update)

            # Wait a moment for the initial SVID to arrive
            for _ in range(50):  # Wait up to 5 seconds
                if self.client.spiffe_id:
                    break
                await asyncio.sleep(0.1)

            if self.client.spiffe_id:
                # Copy initial data from client
                self.spiffe_id = self.client.spiffe_id
                self.certificate = self.client.certificate
                self.private_key = self.client.private_key
                self.trust_bundle = self.client.trust_bundle

                self.logger.info(f"✓ SVID initialized: {self.spiffe_id}")

                # Write certificates to persistent files for mTLS
                self._write_certs_to_files()
                self.logger.info(f"✓ Certificates ready:")
                self.logger.info(f"  Cert: {self.cert_file_path}")
                self.logger.info(f"  Key: {self.key_file_path}")
                self.logger.info(f"  CA: {self.ca_file_path}")

                self.logger.info("✓ Automatic certificate renewal enabled")
            else:
                raise RuntimeError("Failed to fetch SVID from agent")
        except Exception as e:
            self.logger.error(f"SVID initialization failed: {e}")
            raise RuntimeError(f"Failed to initialize SVID: {e}")

    def _write_certs_to_files(self):
        """Write certificates to persistent files for mTLS (internal)"""
        # Create directory if it doesn't exist
        self.cert_dir.mkdir(parents=True, exist_ok=True)

        # Set file paths on first write
        if not self.cert_file_path:
            self.cert_file_path = self.cert_dir / "svid.crt"
            self.key_file_path = self.cert_dir / "svid.key"
            self.ca_file_path = self.cert_dir / "ca.crt"

        # Write certificates atomically (write to temp, then rename)
        # This ensures readers always get complete files
        self._atomic_write(self.cert_file_path, self.certificate)
        self._atomic_write(self.key_file_path, self.private_key)
        self._atomic_write(self.ca_file_path, self.trust_bundle)

        # Set restrictive permissions on private key
        os.chmod(self.key_file_path, 0o600)

    def _atomic_write(self, file_path: Path, content: str):
        """Atomically write content to file"""
        temp_path = file_path.with_suffix(file_path.suffix + '.tmp')
        try:
            with open(temp_path, 'w') as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())  # Ensure written to disk
            # Atomic rename
            temp_path.replace(file_path)
        except Exception as e:
            # Clean up temp file on error
            if temp_path.exists():
                temp_path.unlink()
            raise e

    async def _on_cert_update(self, client: WorkloadAPIClient) -> None:
        """Callback when certificates are renewed by the agent"""
        # Update our cached data
        self.spiffe_id = client.spiffe_id
        self.certificate = client.certificate
        self.private_key = client.private_key
        self.trust_bundle = client.trust_bundle

        # Automatically rewrite temp files for mTLS
        self._write_certs_to_files()

        self.logger.info(f"✓ Certificates automatically renewed for {self.spiffe_id}")
        self.logger.info("✅ mTLS certificate files updated successfully")

    def create_ssl_context_for_server(self) -> ssl.SSLContext:
        """
        Create SSL context for server (uvicorn) that loads certificates from disk.

        This context will read certificates from the persistent files on disk,
        allowing external processes (like uvicorn workers) to access the latest
        certificates even after renewals.

        Returns:
            SSL context configured for mTLS server
        """
        if not self.cert_file_path or not self.key_file_path or not self.ca_file_path:
            raise RuntimeError("Certificates not initialized yet")

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile=str(self.cert_file_path),
            keyfile=str(self.key_file_path)
        )
        context.load_verify_locations(cafile=str(self.ca_file_path))
        context.verify_mode = ssl.CERT_REQUIRED  # Require client certificates

        return context

    def create_ssl_context_for_client(self) -> ssl.SSLContext:
        """
        Create SSL context for client (httpx) that loads certificates from disk.

        This allows httpx clients to read fresh certificates on each request.

        Returns:
            SSL context configured for mTLS client
        """
        if not self.cert_file_path or not self.key_file_path or not self.ca_file_path:
            raise RuntimeError("Certificates not initialized yet")

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(
            certfile=str(self.cert_file_path),
            keyfile=str(self.key_file_path)
        )
        context.load_verify_locations(cafile=str(self.ca_file_path))
        context.check_hostname = False  # SPIFFE IDs are in SAN, not hostname
        context.verify_mode = ssl.CERT_REQUIRED

        return context

    @classmethod
    async def get(cls) -> 'QuickStartSVID':
        """
        Get the singleton instance (must call initialize() first).

        Usage:
            svid = await QuickStartSVID.get()

        Returns:
            QuickStartSVID instance

        Raises:
            RuntimeError: If initialize() not called yet
        """
        if cls._instance is None:
            raise RuntimeError("Call QuickStartSVID.initialize() first")
        return cls._instance

    def get_certificate_dict(self) -> dict:
        """
        Get certificate data as dict for easy passing to HTTP clients.

        Returns:
            Dict with 'cert' and 'key' keys
        """
        return {
            "cert": self.certificate,
            "key": self.private_key
        }
