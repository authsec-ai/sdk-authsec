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
        self._stored_config: Optional[Dict[str, Any]] = None
        self._grpc_client = None  # Only used in direct gRPC mode

    @classmethod
    async def initialize(
        cls,
        socket_path: Optional[str] = None,
        raise_on_disabled: bool = False,
        client_id: Optional[str] = None,
        sdk_manager_url: Optional[str] = None,
        cert_dir: Optional[str] = None
    ) -> Optional['QuickStartSVID']:
        """
        Initialize SPIRE workload identity (singleton pattern)

        This method supports two usage patterns:

        **Pattern 1: MCP Server Integration (uses global config)**
        ```python
        from authsec_sdk import run_mcp_server_with_oauth, QuickStartSVID

        run_mcp_server_with_oauth(
            client_id="your-client-id",
            app_name="My Server",
            spire_socket_path="/run/spire/sockets/agent.sock"
        )

        # In tools:
        svid = await QuickStartSVID.initialize()
        ```

        **Pattern 2: Standalone SPIRE (direct parameters)**
        ```python
        from authsec_sdk import QuickStartSVID

        svid = await QuickStartSVID.initialize(
            client_id="your-client-id",
            socket_path="/run/spire/sockets/agent.sock"
        )
        ```

        This method:
        1. Gets client_id from parameters or global auth config
        2. Collects environment metadata (K8s/Docker labels)
        3. Calls SDK Manager to fetch SVID from local agent
        4. Writes certificates to disk
        5. Starts automatic renewal

        Args:
            socket_path: Path to SPIRE agent socket (default: /run/spire/sockets/agent.sock)
            raise_on_disabled: If True, raises RuntimeError when SPIRE is disabled.
                             If False (default), returns None when SPIRE is disabled.
            client_id: Client ID for SDK Manager authentication (standalone mode).
                      If provided, uses standalone mode. If not, uses global auth config.
            sdk_manager_url: SDK Manager base URL (standalone mode only).
                           Default: https://dev.api.authsec.dev/sdkmgr/spire
            cert_dir: Directory to store certificates (default: /tmp/spiffe-certs)

        Returns:
            QuickStartSVID instance with SVID ready for mTLS, or None if SPIRE is disabled

        Raises:
            RuntimeError: If SPIRE fetch fails (or if raise_on_disabled=True and SPIRE is disabled)
        """
        async with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
                result = await cls._instance._fetch(
                    socket_path=socket_path,
                    raise_on_disabled=raise_on_disabled,
                    client_id=client_id,
                    sdk_manager_url=sdk_manager_url,
                    cert_dir=cert_dir
                )
                if result is False:
                    # SPIRE is disabled and raise_on_disabled=False
                    cls._instance = None
                    return None
            return cls._instance

    async def _fetch(
        self,
        socket_path: Optional[str] = None,
        raise_on_disabled: bool = False,
        client_id: Optional[str] = None,
        sdk_manager_url: Optional[str] = None,
        cert_dir: Optional[str] = None
    ) -> bool:
        """
        Fetch SVID from either SDK Manager or direct gRPC

        Supports three modes:
        1. MCP Server mode: Uses global auth config (no client_id, global config exists)
        2. SDK Manager mode: Uses REST API with client_id (client_id provided)
        3. Direct gRPC mode: Connects directly to agent (no client_id, no global config)

        Returns:
            True if successful, False if SPIRE is disabled (and raise_on_disabled=False)
        """
        # Determine mode
        use_sdk_manager = False
        config = None

        if client_id:
            # SDK Manager mode with explicit client_id
            use_sdk_manager = True
            config = {
                "client_id": client_id,
                "sdk_manager_url": sdk_manager_url or "https://dev.api.authsec.dev/sdkmgr/spire",
                "socket_path": socket_path or "/run/spire/sockets/agent.sock",
                "cert_dir": cert_dir or "/tmp/spiffe-certs",
                "timeout": 10,
                "mode": "sdk_manager"
            }
            logger.info("Using SDK Manager mode (client_id provided)")
        else:
            # Try to get global config (MCP Server mode)
            try:
                config = _get_spire_config()
                config["mode"] = "mcp_server"
                use_sdk_manager = True
                logger.info("Using MCP Server mode (global config)")

                # Override socket_path if provided
                if socket_path:
                    config["socket_path"] = socket_path
                if cert_dir:
                    config["cert_dir"] = cert_dir

            except RuntimeError as e:
                # No global config - check if it's because SPIRE is disabled or not configured
                error_msg = str(e)
                if "not enabled" in error_msg.lower():
                    if raise_on_disabled:
                        raise
                    else:
                        logger.warning("SPIRE is not enabled. Skipping SVID fetch.")
                        return False
                elif "not configured" in error_msg.lower():
                    # No global config - use direct gRPC mode
                    use_sdk_manager = False
                    config = {
                        "socket_path": socket_path or "/run/spire/sockets/agent.sock",
                        "cert_dir": cert_dir or "/tmp/spiffe-certs",
                        "mode": "direct_grpc"
                    }
                    logger.info("Using direct gRPC mode (no auth config)")
                else:
                    # Other error
                    raise

        # Fetch SVID based on mode
        if use_sdk_manager:
            # Use SDK Manager REST API
            return await self._fetch_via_sdk_manager(config)
        else:
            # Use direct gRPC connection to agent
            return await self._fetch_via_grpc(config)

    async def _fetch_via_sdk_manager(self, config: Dict[str, Any]) -> bool:
        """Fetch SVID via SDK Manager REST API"""
        logger.info("Fetching SPIFFE SVID via SDK Manager...")

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
                        "socket_path": config["socket_path"],
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

            # Store config for renewal
            self._stored_config = config

            logger.info(f"✓ SVID initialized: {self.svid.spiffe_id}")
            logger.info("✓ Certificates ready for mTLS")

            # Start automatic renewal (every 30 minutes)
            self.running = True
            self.renewal_task = asyncio.create_task(self._auto_renewal_loop())

            return True

        except Exception as e:
            logger.error(f"SVID initialization failed: {str(e)}", exc_info=True)
            raise RuntimeError(f"Failed to initialize SVID: {str(e)}")

    async def _fetch_via_grpc(self, config: Dict[str, Any]) -> bool:
        """Fetch SVID via direct gRPC connection to SPIRE agent"""
        logger.info("Fetching SPIFFE SVID via direct gRPC...")

        try:
            # Import the gRPC client (from tests/spire_sdk)
            import sys
            from pathlib import Path as PathLib

            # Add parent directory to path to import spire_sdk
            parent_dir = PathLib(__file__).parent.parent.parent
            if str(parent_dir) not in sys.path:
                sys.path.insert(0, str(parent_dir))

            from spire_sdk.spiffe_workload_api.client import WorkloadAPIClient

            # Create gRPC client
            grpc_client = WorkloadAPIClient(socket_path=config["socket_path"])
            await grpc_client.connect()

            # Fetch SVID once
            success = await grpc_client.fetch_x509_svid_once()
            if not success:
                raise RuntimeError("Failed to fetch SVID from agent")

            # Create WorkloadSVID object
            self.svid = WorkloadSVID(
                spiffe_id=grpc_client.spiffe_id,
                certificate=grpc_client.certificate,
                private_key=grpc_client.private_key,
                trust_bundle=grpc_client.trust_bundle,
                cert_dir=Path(config["cert_dir"])
            )

            # Store config and gRPC client for renewal
            self._stored_config = config
            self._grpc_client = grpc_client

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
        """Renew SVID (supports both SDK Manager and direct gRPC modes)"""
        # Use stored config from initialization
        if not self._stored_config:
            raise RuntimeError("SVID config not stored")

        config = self._stored_config
        mode = config.get("mode", "sdk_manager")

        if mode == "direct_grpc":
            # Direct gRPC mode: Fetch from agent
            await self._renew_via_grpc()
        else:
            # SDK Manager mode: Call REST API
            await self._renew_via_sdk_manager()

        logger.info("✅ SVID renewed successfully")

    async def _renew_via_sdk_manager(self):
        """Renew SVID via SDK Manager REST API"""
        config = self._stored_config
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

    async def _renew_via_grpc(self):
        """Renew SVID via direct gRPC connection"""
        if not self._grpc_client:
            raise RuntimeError("gRPC client not available")

        # Fetch fresh SVID
        success = await self._grpc_client.fetch_x509_svid_once()
        if not success:
            raise RuntimeError("Failed to renew SVID from agent")

        # Refresh SVID data
        self.svid.refresh(
            certificate=self._grpc_client.certificate,
            private_key=self._grpc_client.private_key,
            trust_bundle=self._grpc_client.trust_bundle
        )

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

        # Disconnect gRPC client if in direct mode
        if self._grpc_client:
            await self._grpc_client.disconnect()
            self._grpc_client = None

        logger.info("SVID renewal stopped")
