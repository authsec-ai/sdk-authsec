"""
SPIRE SDK - Simplified Workload Identity
Provides easy SPIFFE SVID integration via AuthSec SDK Manager
"""

import os
import ssl
import asyncio
import aiohttp
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


def _get_spire_config():
    """
    Get SPIRE configuration from global auth config

    Uses the same client_id and base URL as MCP auth
    """
    # Import here to avoid circular dependency
    from . import AuthSec_SDK as sdk

    if not sdk._config.get("client_id"):
        raise RuntimeError("Auth not configured. Call configure_auth() or run_mcp_server_with_oauth() first.")

    # Check if SPIRE is enabled
    if not sdk._config.get("spire_enabled", False):
        raise RuntimeError(
            "SPIRE is not enabled. To enable SPIRE, pass 'spire_socket_path' parameter to run_mcp_server_with_oauth().\n"
            "Example: run_mcp_server_with_oauth(..., spire_socket_path='/run/spire/sockets/agent.sock')"
        )

    # Get base SDK manager URL and replace /mcp-auth with /spire
    base_url = sdk._config.get("auth_service_url", "https://dev.api.authsec.dev/sdkmgr/mcp-auth")
    spire_url = base_url.replace("/mcp-auth", "/spire")

    return {
        "client_id": sdk._config["client_id"],
        "sdk_manager_url": spire_url,
        "socket_path": sdk._config.get("spire_socket_path", "/run/spire/sockets/agent.sock"),
        "cert_dir": sdk._config.get("spire_cert_dir", "/tmp/spiffe-certs"),
        "timeout": sdk._config.get("timeout", 10)
    }


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

        IMPORTANT: Always call this for each request to get fresh certificates!

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

    This replaces the original gRPC-based QuickStartSVID with a REST-based version
    that communicates with AuthSec SDK Manager.

    Usage:
        from AuthSec_SDK import configure_spire, QuickStartSVID

        # Configure
        configure_spire(tenant_id="your-tenant-id")

        # Initialize (fetches SVID from agent via SDK Manager)
        svid = await QuickStartSVID.initialize()

        # Use for mTLS
        ssl_context = svid.create_ssl_context_for_client()
    """

    _instance: Optional['QuickStartSVID'] = None
    _lock = asyncio.Lock()

    def __init__(self):
        self.svid: Optional[WorkloadSVID] = None
        self.renewal_task: Optional[asyncio.Task] = None
        self.running = False

    @classmethod
    async def initialize(
        cls,
        socket_path: Optional[str] = None,
        raise_on_disabled: bool = False
    ) -> Optional['QuickStartSVID']:
        """
        Initialize SPIRE workload identity (singleton pattern)

        This method:
        1. Gets client_id from global auth config
        2. Collects environment metadata (K8s/Docker labels)
        3. Calls SDK Manager to fetch SVID from local agent
        4. Writes certificates to disk
        5. Starts automatic renewal

        Args:
            socket_path: Override default socket path
            raise_on_disabled: If True, raises RuntimeError when SPIRE is disabled.
                             If False (default), returns None when SPIRE is disabled.

        Returns:
            QuickStartSVID instance with SVID ready for mTLS, or None if SPIRE is disabled

        Raises:
            RuntimeError: If SPIRE fetch fails (or if raise_on_disabled=True and SPIRE is disabled)
        """
        async with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
                result = await cls._instance._fetch(socket_path, raise_on_disabled)
                if result is False:
                    # SPIRE is disabled and raise_on_disabled=False
                    cls._instance = None
                    return None
            return cls._instance

    async def _fetch(
        self,
        socket_path: Optional[str] = None,
        raise_on_disabled: bool = False
    ) -> bool:
        """
        Fetch SVID from SDK Manager

        Returns:
            True if successful, False if SPIRE is disabled (and raise_on_disabled=False)
        """
        logger.info("Fetching SPIFFE SVID via SDK Manager...")

        # Get config from global auth settings
        try:
            config = _get_spire_config()
        except RuntimeError as e:
            # SPIRE is not enabled
            error_msg = str(e)
            if "not enabled" in error_msg.lower():
                if raise_on_disabled:
                    raise
                else:
                    logger.warning("SPIRE is not enabled. Skipping SVID fetch.")
                    return False
            else:
                # Other RuntimeError, re-raise
                raise

        socket_path = socket_path or config["socket_path"]

        # Collect environment metadata for attestation
        environment_metadata = self._collect_environment_metadata()

        # Call SDK Manager to fetch SVID
        try:
            timeout = aiohttp.ClientTimeout(total=config["timeout"])

            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    f"{config['sdk_manager_url']}/workload/initialize",
                    json={
                        "client_id": config["client_id"],
                        "socket_path": socket_path,
                        "environment_metadata": environment_metadata
                    },
                    headers={"Content-Type": "application/json"}
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise RuntimeError(f"SVID fetch failed: {error_text}")

                    data = await response.json()

            # Create WorkloadSVID object
            self.svid = WorkloadSVID(
                spiffe_id=data["spiffe_id"],
                certificate=data["certificate"],
                private_key=data["private_key"],
                trust_bundle=data["trust_bundle"],
                cert_dir=Path(config["cert_dir"])
            )

            logger.info(f"✓ SVID initialized: {self.svid.spiffe_id}")
            logger.info("✓ Certificates ready for mTLS")

            # Start automatic renewal (every 30 minutes)
            self.running = True
            self.renewal_task = asyncio.create_task(self._auto_renewal_loop())

            return True

        except Exception as e:
            logger.error(f"SVID initialization failed: {str(e)}", exc_info=True)
            raise RuntimeError(f"Failed to initialize SVID: {str(e)}")

    def _collect_environment_metadata(self) -> Dict[str, str]:
        """
        Collect environment metadata for workload attestation

        Returns K8s/Docker environment variables that the agent uses
        for selector collection
        """
        metadata = {}

        # Kubernetes metadata
        k8s_vars = [
            'POD_NAME',
            'POD_NAMESPACE',
            'POD_UID',
            'SERVICE_ACCOUNT',
            'POD_LABEL_APP'
        ]

        for var in k8s_vars:
            value = os.getenv(var)
            if value:
                metadata[var] = value

        # Docker metadata
        docker_vars = [
            'DOCKER_CONTAINER_ID',
            'DOCKER_CONTAINER_NAME',
            'DOCKER_IMAGE_NAME'
        ]

        for var in docker_vars:
            value = os.getenv(var)
            if value:
                metadata[var] = value

        # Docker labels (prefixed with DOCKER_LABEL_)
        for key, value in os.environ.items():
            if key.startswith('DOCKER_LABEL_'):
                metadata[key] = value

        logger.debug(f"Collected environment metadata: {list(metadata.keys())}")
        return metadata

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
        """Renew SVID from SDK Manager"""
        config = _get_spire_config()
        environment_metadata = self._collect_environment_metadata()

        timeout = aiohttp.ClientTimeout(total=config["timeout"])

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                f"{config['sdk_manager_url']}/workload/renew",
                json={
                    "client_id": config["client_id"],
                    "socket_path": config["socket_path"],
                    "environment_metadata": environment_metadata
                },
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise RuntimeError(f"SVID renewal failed: {error_text}")

                data = await response.json()

        # Refresh SVID data
        self.svid.refresh(
            certificate=data["certificate"],
            private_key=data["private_key"],
            trust_bundle=data["trust_bundle"]
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
        """Shutdown SVID renewal"""
        self.running = False
        if self.renewal_task:
            self.renewal_task.cancel()
            try:
                await self.renewal_task
            except asyncio.CancelledError:
                pass
        logger.info("SVID renewal stopped")
