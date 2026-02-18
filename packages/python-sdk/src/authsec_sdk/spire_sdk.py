"""
SPIRE SDK - Simple Workload Identity Wrapper
Provides easy SPIFFE SVID integration using direct gRPC to SPIRE agent
"""

import os
import ssl
import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass

# Import from local spiffe_workload_api package
from .spiffe_workload_api.client import WorkloadAPIClient

logger = logging.getLogger(__name__)


@dataclass
class WorkloadSVID:
    """
    Workload SVID data

    Contains the X.509 certificate, private key, and trust bundle
    for mTLS communication
    """
    spiffe_id: str
    certificate: str
    private_key: str
    trust_bundle: str
    cert_dir: Path

    # Certificate file paths (auto-managed)
    cert_file_path: Optional[Path] = None
    key_file_path: Optional[Path] = None
    ca_file_path: Optional[Path] = None

    def __post_init__(self):
        """Initialize certificate files"""
        self._write_certs_to_files()

    def _write_certs_to_files(self):
        """Write certificates to persistent files for mTLS"""
        # Create directory if it doesn't exist
        self.cert_dir.mkdir(parents=True, exist_ok=True)

        # Set file paths
        self.cert_file_path = self.cert_dir / "svid.crt"
        self.key_file_path = self.cert_dir / "svid.key"
        self.ca_file_path = self.cert_dir / "ca.crt"

        # Write certificates atomically
        self._atomic_write(self.cert_file_path, self.certificate)
        self._atomic_write(self.key_file_path, self.private_key)
        self._atomic_write(self.ca_file_path, self.trust_bundle)

        # Set restrictive permissions on private key
        os.chmod(self.key_file_path, 0o600)

        logger.info("✓ Certificates written to disk:")
        logger.info(f"  Cert: {self.cert_file_path}")
        logger.info(f"  Key: {self.key_file_path}")
        logger.info(f"  CA: {self.ca_file_path}")

    def _atomic_write(self, file_path: Path, content: str):
        """Atomically write content to file"""
        temp_path = file_path.with_suffix(file_path.suffix + '.tmp')
        try:
            with open(temp_path, 'w') as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            temp_path.replace(file_path)
        except Exception as e:
            if temp_path.exists():
                temp_path.unlink()
            raise e

    def create_ssl_context_for_server(self) -> ssl.SSLContext:
        """
        Create SSL context for server (uvicorn/FastAPI)

        Returns:
            SSL context configured for mTLS server
        """
        if not self.cert_file_path or not self.key_file_path or not self.ca_file_path:
            raise RuntimeError("Certificates not initialized")

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile=str(self.cert_file_path),
            keyfile=str(self.key_file_path)
        )
        context.load_verify_locations(cafile=str(self.ca_file_path))
        context.verify_mode = ssl.CERT_REQUIRED

        return context

    def create_ssl_context_for_client(self) -> ssl.SSLContext:
        """
        Create SSL context for client (httpx/aiohttp)

        Returns:
            SSL context configured for mTLS client
        """
        if not self.cert_file_path or not self.key_file_path or not self.ca_file_path:
            raise RuntimeError("Certificates not initialized")

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(
            certfile=str(self.cert_file_path),
            keyfile=str(self.key_file_path)
        )
        context.load_verify_locations(cafile=str(self.ca_file_path))
        context.check_hostname = False  # SPIFFE IDs are in SAN, not hostname
        context.verify_mode = ssl.CERT_REQUIRED

        return context

    def refresh(self, certificate: str, private_key: str, trust_bundle: str):
        """
        Refresh SVID data (called during renewal)

        Args:
            certificate: New certificate PEM
            private_key: New private key PEM
            trust_bundle: New trust bundle PEM
        """
        self.certificate = certificate
        self.private_key = private_key
        self.trust_bundle = trust_bundle
        self._write_certs_to_files()
        logger.info(f"✓ SVID refreshed: {self.spiffe_id}")


class QuickStartSVID:
    """
    Simplified SPIRE SVID integration

    Connects directly to SPIRE agent via gRPC and fetches X.509-SVIDs.

    Usage:
        from AuthSec_SDK import QuickStartSVID

        # Initialize (fetches SVID from agent)
        svid = await QuickStartSVID.initialize(
            socket_path="/run/spire/sockets/agent.sock"
        )

        # Use for mTLS
        ssl_context = svid.create_ssl_context_for_client()
    """

    _instance: Optional['QuickStartSVID'] = None
    _lock = asyncio.Lock()

    def __init__(self):
        self.svid: Optional[WorkloadSVID] = None
        self.grpc_client: Optional[WorkloadAPIClient] = None
        self.renewal_task: Optional[asyncio.Task] = None
        self.running = False

    @classmethod
    async def initialize(
        cls,
        socket_path: str = "/run/spire/sockets/agent.sock",
        cert_dir: Optional[str] = None
    ) -> 'QuickStartSVID':
        """
        Initialize SPIRE workload identity (singleton pattern)

        This method:
        1. Connects to SPIRE agent via gRPC
        2. Fetches X.509-SVID from agent
        3. Writes certificates to disk
        4. Starts automatic renewal (every 30 minutes)

        Args:
            socket_path: Path to SPIRE agent socket
            cert_dir: Directory to store certificates (default: /tmp/spiffe-certs)

        Returns:
            QuickStartSVID instance with SVID ready for mTLS

        Raises:
            RuntimeError: If SVID fetch fails
        """
        async with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
                await cls._instance._fetch(socket_path, cert_dir)
            return cls._instance

    async def _fetch(
        self,
        socket_path: str,
        cert_dir: Optional[str] = None
    ):
        """Fetch SVID from SPIRE agent via gRPC"""
        logger.info("Fetching SPIFFE SVID via gRPC...")

        try:
            # Create gRPC client
            self.grpc_client = WorkloadAPIClient(socket_path=socket_path)
            await self.grpc_client.connect()

            # Fetch SVID
            success = await self.grpc_client.fetch_x509_svid_once()
            if not success:
                raise RuntimeError("Failed to fetch SVID from agent")

            # Create WorkloadSVID object
            self.svid = WorkloadSVID(
                spiffe_id=self.grpc_client.spiffe_id,
                certificate=self.grpc_client.certificate,
                private_key=self.grpc_client.private_key,
                trust_bundle=self.grpc_client.trust_bundle,
                cert_dir=Path(cert_dir or "/tmp/spiffe-certs")
            )

            logger.info(f"✓ SVID initialized: {self.svid.spiffe_id}")
            logger.info("✓ Certificates ready for mTLS")

            # Start automatic renewal (every 30 minutes)
            self.running = True
            self.renewal_task = asyncio.create_task(self._auto_renewal_loop())

        except Exception as e:
            logger.error(f"SVID initialization failed: {str(e)}", exc_info=True)
            raise RuntimeError(f"Failed to initialize SVID: {str(e)}")

    async def _auto_renewal_loop(self):
        """
        Background task for automatic SVID renewal

        Renews SVID every 30 minutes to ensure fresh certificates
        """
        logger.info("✓ Automatic SVID renewal enabled (30 min interval)")

        while self.running:
            try:
                # Wait 30 minutes
                await asyncio.sleep(1800)

                if not self.running:
                    break

                # Renew SVID
                logger.info("Renewing SVID...")
                await self._renew_svid()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"SVID renewal failed: {str(e)}", exc_info=True)
                # Continue trying

    async def _renew_svid(self):
        """Renew SVID from agent"""
        if not self.grpc_client:
            raise RuntimeError("gRPC client not available")

        # Fetch fresh SVID
        success = await self.grpc_client.fetch_x509_svid_once()
        if not success:
            raise RuntimeError("Failed to renew SVID from agent")

        # Refresh SVID data
        self.svid.refresh(
            certificate=self.grpc_client.certificate,
            private_key=self.grpc_client.private_key,
            trust_bundle=self.grpc_client.trust_bundle
        )

        logger.info("✅ SVID renewed successfully")

    @classmethod
    async def get(cls) -> 'QuickStartSVID':
        """
        Get the singleton instance (must call initialize() first)

        Returns:
            QuickStartSVID instance

        Raises:
            RuntimeError: If initialize() not called yet
        """
        if cls._instance is None:
            raise RuntimeError("Call QuickStartSVID.initialize() first")
        return cls._instance

    @property
    def spiffe_id(self) -> str:
        """Get SPIFFE ID"""
        if not self.svid:
            raise RuntimeError("SVID not initialized")
        return self.svid.spiffe_id

    @property
    def certificate(self) -> str:
        """Get certificate PEM"""
        if not self.svid:
            raise RuntimeError("SVID not initialized")
        return self.svid.certificate

    @property
    def private_key(self) -> str:
        """Get private key PEM"""
        if not self.svid:
            raise RuntimeError("SVID not initialized")
        return self.svid.private_key

    @property
    def trust_bundle(self) -> str:
        """Get trust bundle PEM"""
        if not self.svid:
            raise RuntimeError("SVID not initialized")
        return self.svid.trust_bundle

    @property
    def cert_file_path(self) -> Path:
        """Get certificate file path"""
        if not self.svid:
            raise RuntimeError("SVID not initialized")
        return self.svid.cert_file_path

    @property
    def key_file_path(self) -> Path:
        """Get private key file path"""
        if not self.svid:
            raise RuntimeError("SVID not initialized")
        return self.svid.key_file_path

    @property
    def ca_file_path(self) -> Path:
        """Get CA bundle file path"""
        if not self.svid:
            raise RuntimeError("SVID not initialized")
        return self.svid.ca_file_path

    def create_ssl_context_for_server(self) -> ssl.SSLContext:
        """Create SSL context for server"""
        if not self.svid:
            raise RuntimeError("SVID not initialized")
        return self.svid.create_ssl_context_for_server()

    def create_ssl_context_for_client(self) -> ssl.SSLContext:
        """Create SSL context for client"""
        if not self.svid:
            raise RuntimeError("SVID not initialized")
        return self.svid.create_ssl_context_for_client()

    async def shutdown(self):
        """Shutdown SVID renewal and gRPC client"""
        self.running = False
        if self.renewal_task:
            self.renewal_task.cancel()
            try:
                await self.renewal_task
            except asyncio.CancelledError:
                pass

        if self.grpc_client:
            await self.grpc_client.disconnect()
            self.grpc_client = None

        logger.info("SVID renewal stopped")
