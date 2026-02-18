"""
SPIFFE Workload API - gRPC Client

Client library for workloads to fetch SVIDs from the gRPC Workload API.
Supports streaming X.509-SVIDs with automatic rotation.
"""

import asyncio
import logging
import os
from typing import Optional, Dict, List, AsyncIterator
import grpc
from grpc import aio

from .api import workload_pb2, workload_pb2_grpc


class WorkloadAPIClient:
    """
    gRPC client for SPIFFE Workload API

    Connects to the agent via Unix socket and fetches SVIDs.
    """

    def __init__(
        self,
        socket_path: str = "/tmp/spire-agent/public/api.sock",
        logger: Optional[logging.Logger] = None
    ):
        self.socket_path = socket_path
        self.logger = logger or logging.getLogger(__name__)

        # Current SVID data
        self.spiffe_id: Optional[str] = None
        self.certificate: Optional[str] = None
        self.private_key: Optional[str] = None
        self.trust_bundle: Optional[str] = None

        # gRPC channel and stub
        self.channel: Optional[aio.Channel] = None
        self.stub: Optional[workload_pb2_grpc.SpiffeWorkloadAPIStub] = None

        # Background task for streaming updates
        self.stream_task: Optional[asyncio.Task] = None
        self.running = False

    async def connect(self):
        """Connect to the Workload API"""
        self.logger.info("Connecting to gRPC Workload API")
        self.logger.info(f"  Socket: {self.socket_path}")

        # Support multiple socket types:
        # - tcp://host:port (Windows, VMs, K8s with TCP)
        # - unix:///path/to/socket (Unix/Linux)
        # - /path/to/socket (Unix/Linux shorthand)
        if self.socket_path.startswith("tcp://"):
            # TCP socket (Windows, VMs, K8s service endpoints)
            address = self.socket_path.replace("tcp://", "")
            self.logger.info(f"  Using TCP socket: {address}")
            self.channel = aio.insecure_channel(address)
        elif self.socket_path.startswith("unix://"):
            # Unix socket with unix:// prefix (K8s hostPath volumes)
            unix_path = self.socket_path.replace("unix://", "")
            self.logger.info(f"  Using Unix socket: {unix_path}")
            self.channel = aio.insecure_channel(f'unix:{unix_path}')
        else:
            # Standard Unix socket path (default for SPIRE on Linux/K8s)
            self.logger.info(f"  Using Unix socket")
            self.channel = aio.insecure_channel(f'unix:{self.socket_path}')

        # Create stub
        self.stub = workload_pb2_grpc.SpiffeWorkloadAPIStub(self.channel)

        self.logger.info("✓ Connected to Workload API")

    async def disconnect(self):
        """Disconnect from Workload API"""
        self.running = False

        if self.stream_task:
            self.stream_task.cancel()
            try:
                await self.stream_task
            except asyncio.CancelledError:
                pass

        if self.channel:
            await self.channel.close()

        self.logger.info("Disconnected from Workload API")

    async def fetch_x509_svid_once(self) -> bool:
        """
        Fetch X.509-SVID once (single request/response)

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.stub:
                await self.connect()

            # Create request
            request = workload_pb2.X509SVIDRequest()

            # For TCP sockets, send PID in gRPC metadata
            # (Unix sockets use SO_PEERCRED instead)
            metadata = []
            if self.socket_path.startswith("tcp://"):
                pid = os.getpid()
                metadata.append(('x-pid', str(pid)))
                self.logger.debug(f"Sending PID {pid} in gRPC metadata")

            # Send Kubernetes metadata if available (for cross-pod attestation)
            k8s_namespace = os.getenv('POD_NAMESPACE')
            k8s_pod_name = os.getenv('POD_NAME')
            k8s_pod_uid = os.getenv('POD_UID')
            k8s_service_account = os.getenv('SERVICE_ACCOUNT')
            k8s_pod_label_app = os.getenv('POD_LABEL_APP')

            if k8s_namespace:
                metadata.append(('x-k8s-namespace', k8s_namespace))
                self.logger.debug(f"Sending K8s namespace: {k8s_namespace}")
            if k8s_pod_name:
                metadata.append(('x-k8s-pod-name', k8s_pod_name))
                self.logger.debug(f"Sending K8s pod name: {k8s_pod_name}")
            if k8s_pod_uid:
                metadata.append(('x-k8s-pod-uid', k8s_pod_uid))
                self.logger.debug(f"Sending K8s pod UID: {k8s_pod_uid}")
            if k8s_service_account:
                metadata.append(('x-k8s-service-account', k8s_service_account))
                self.logger.debug(f"Sending K8s service account: {k8s_service_account}")
            if k8s_pod_label_app:
                metadata.append(('x-k8s-pod-label-app', k8s_pod_label_app))
                self.logger.debug(f"Sending K8s pod label app: {k8s_pod_label_app}")

            # Send Docker metadata if available (for Docker workload attestation)
            # These can be set as environment variables in docker-compose
            docker_container_id = os.getenv('DOCKER_CONTAINER_ID')
            docker_container_name = os.getenv('DOCKER_CONTAINER_NAME')
            docker_image_name = os.getenv('DOCKER_IMAGE_NAME')

            if docker_container_id:
                metadata.append(('x-docker-container-id', docker_container_id))
                self.logger.debug(f"Sending Docker container ID: {docker_container_id}")
            if docker_container_name:
                metadata.append(('x-docker-container-name', docker_container_name))
                self.logger.debug(f"Sending Docker container name: {docker_container_name}")
            if docker_image_name:
                metadata.append(('x-docker-image-name', docker_image_name))
                self.logger.debug(f"Sending Docker image name: {docker_image_name}")

            # Send Docker labels as metadata (prefixed with DOCKER_LABEL_)
            for key, value in os.environ.items():
                if key.startswith('DOCKER_LABEL_'):
                    label_name = key[13:].lower()  # Remove 'DOCKER_LABEL_' prefix
                    metadata.append((f'x-docker-label-{label_name}', value))
                    self.logger.debug(f"Sending Docker label {label_name}: {value}")

            # DEBUG: Print metadata being sent
            print(f"[SDK DEBUG] Metadata being sent to agent: {metadata}", flush=True)
            print(f"[SDK DEBUG] Metadata tuple: {tuple(metadata)}", flush=True)

            # Call FetchX509SVID - get first response from stream
            # Convert metadata list to tuple for gRPC
            stream = self.stub.FetchX509SVID(request, metadata=tuple(metadata))

            # Get first response
            response = await stream.read()

            if response and len(response.svids) > 0:
                svid = response.svids[0]

                self.spiffe_id = svid.spiffe_id
                self.certificate = svid.x509_svid.decode('utf-8')
                self.private_key = svid.x509_svid_key.decode('utf-8')
                self.trust_bundle = svid.bundle.decode('utf-8')

                self.logger.info("✓ Fetched X.509-SVID")
                self.logger.info(f"  SPIFFE ID: {self.spiffe_id}")
                self.logger.info(f"  Certificate issued and ready to use")
                self.logger.info(f"  Trust Bundle received from agent")

                return True
            else:
                self.logger.error("No SVIDs in response")
                return False

        except grpc.RpcError as e:
            self.logger.error(f"gRPC error fetching SVID: {e.code()} - {e.details()}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to fetch SVID: {e}")
            return False

    async def start_streaming(self, on_update=None):
        """
        Start streaming X.509-SVID updates

        Args:
            on_update: Optional callback function called when SVID is updated
        """
        self.running = True

        if not self.stub:
            await self.connect()

        self.logger.info("Starting X.509-SVID stream...")

        # Start background streaming task
        self.stream_task = asyncio.create_task(
            self._stream_x509_svids(on_update)
        )

    async def _stream_x509_svids(self, on_update=None):
        """Background task to stream SVID updates"""
        try:
            # Create request
            request = workload_pb2.X509SVIDRequest()

            # For TCP sockets, send PID in gRPC metadata
            metadata = []
            if self.socket_path.startswith("tcp://"):
                pid = os.getpid()
                metadata.append(('x-pid', str(pid)))
                self.logger.debug(f"Sending PID {pid} in gRPC metadata for streaming")

            # Send Kubernetes metadata if available (for cross-pod attestation)
            k8s_namespace = os.getenv('POD_NAMESPACE')
            k8s_pod_name = os.getenv('POD_NAME')
            k8s_pod_uid = os.getenv('POD_UID')
            k8s_service_account = os.getenv('SERVICE_ACCOUNT')
            k8s_pod_label_app = os.getenv('POD_LABEL_APP')

            if k8s_namespace:
                metadata.append(('x-k8s-namespace', k8s_namespace))
            if k8s_pod_name:
                metadata.append(('x-k8s-pod-name', k8s_pod_name))
            if k8s_pod_uid:
                metadata.append(('x-k8s-pod-uid', k8s_pod_uid))
            if k8s_service_account:
                metadata.append(('x-k8s-service-account', k8s_service_account))
            if k8s_pod_label_app:
                metadata.append(('x-k8s-pod-label-app', k8s_pod_label_app))

            # Send Docker metadata if available (for Docker workload attestation)
            docker_container_id = os.getenv('DOCKER_CONTAINER_ID')
            docker_container_name = os.getenv('DOCKER_CONTAINER_NAME')
            docker_image_name = os.getenv('DOCKER_IMAGE_NAME')

            if docker_container_id:
                metadata.append(('x-docker-container-id', docker_container_id))
            if docker_container_name:
                metadata.append(('x-docker-container-name', docker_container_name))
            if docker_image_name:
                metadata.append(('x-docker-image-name', docker_image_name))

            # Send Docker labels as metadata (prefixed with DOCKER_LABEL_)
            for key, value in os.environ.items():
                if key.startswith('DOCKER_LABEL_'):
                    label_name = key[13:].lower()  # Remove 'DOCKER_LABEL_' prefix
                    metadata.append((f'x-docker-label-{label_name}', value))

            # DEBUG: Print metadata being sent
            print(f"[SDK DEBUG STREAM] Metadata being sent to agent: {metadata}", flush=True)
            print(f"[SDK DEBUG STREAM] Metadata tuple: {tuple(metadata)}", flush=True)

            # Open streaming RPC - Convert metadata list to tuple for gRPC
            stream = self.stub.FetchX509SVID(request, metadata=tuple(metadata))

            self.logger.info("✓ Streaming X.509-SVIDs...")

            # Read responses from stream
            async for response in stream:
                if not self.running:
                    break

                if len(response.svids) > 0:
                    svid = response.svids[0]

                    # Update cached SVID
                    self.spiffe_id = svid.spiffe_id
                    self.certificate = svid.x509_svid.decode('utf-8')
                    self.private_key = svid.x509_svid_key.decode('utf-8')
                    self.trust_bundle = svid.bundle.decode('utf-8')

                    self.logger.info("✓ Received SVID update")
                    self.logger.info(f"  SPIFFE ID: {self.spiffe_id}")
                    self.logger.info(f"  Certificate refreshed from agent")
                    self.logger.info(f"  Trust Bundle updated")

                    # Call update callback if provided
                    if on_update:
                        await on_update(self)

        except asyncio.CancelledError:
            self.logger.info("SVID stream cancelled")
        except grpc.RpcError as e:
            self.logger.error(f"gRPC stream error: {e.code()} - {e.details()}")
        except Exception as e:
            self.logger.error(f"Error in SVID stream: {e}")

    async def fetch_jwt_svid(
        self,
        audience: List[str],
        spiffe_id: Optional[str] = None
    ) -> Optional[str]:
        """
        Fetch JWT-SVID

        Args:
            audience: List of audiences for the JWT
            spiffe_id: Optional SPIFFE ID (defaults to workload's identity)

        Returns:
            JWT token or None
        """
        try:
            if not self.stub:
                await self.connect()

            # Create request
            request = workload_pb2.JWTSVIDRequest(
                audience=audience,
                spiffe_id=spiffe_id or ""
            )

            # Call FetchJWTSVID
            response = await self.stub.FetchJWTSVID(request)

            if len(response.svids) > 0:
                jwt_svid = response.svids[0]
                self.logger.info("✓ Fetched JWT-SVID")
                self.logger.info(f"  SPIFFE ID: {jwt_svid.spiffe_id}")
                self.logger.info(f"  Audience: {audience}")
                return jwt_svid.svid
            else:
                self.logger.error("No JWT-SVIDs in response")
                return None

        except grpc.RpcError as e:
            self.logger.error(f"gRPC error fetching JWT-SVID: {e.code()} - {e.details()}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to fetch JWT-SVID: {e}")
            return None

    async def validate_jwt_svid(
        self,
        token: str,
        audience: str
    ) -> Optional[Dict]:
        """
        Validate JWT-SVID

        Args:
            token: JWT token to validate
            audience: Expected audience

        Returns:
            Validation result with spiffe_id and claims, or None if invalid
        """
        try:
            if not self.stub:
                await self.connect()

            # Create request
            request = workload_pb2.ValidateJWTSVIDRequest(
                svid=token,
                audience=audience
            )

            # Call ValidateJWTSVID
            response = await self.stub.ValidateJWTSVID(request)

            self.logger.info("✓ JWT-SVID validated")
            self.logger.info(f"  SPIFFE ID: {response.spiffe_id}")

            return {
                'spiffe_id': response.spiffe_id,
                'claims': dict(response.claims)
            }

        except grpc.RpcError as e:
            self.logger.error(f"gRPC error validating JWT-SVID: {e.code()} - {e.details()}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to validate JWT-SVID: {e}")
            return None

    async def fetch_x509_bundles_stream(self) -> AsyncIterator[Dict[str, bytes]]:
        """
        Stream X.509 trust bundles

        Yields:
            Dictionary of trust domain -> bundle
        """
        try:
            if not self.stub:
                await self.connect()

            # Create request
            request = workload_pb2.X509BundlesRequest()

            # Open streaming RPC
            stream = self.stub.FetchX509Bundles(request)

            self.logger.info("Streaming X.509 bundles...")

            # Read responses from stream
            async for response in stream:
                yield dict(response.bundles)

        except grpc.RpcError as e:
            self.logger.error(f"gRPC bundle stream error: {e.code()} - {e.details()}")
        except Exception as e:
            self.logger.error(f"Error in bundle stream: {e}")

    def get_mtls_config(self) -> Optional[Dict]:
        """
        Get mTLS configuration for HTTP clients

        Returns:
            Dictionary with cert, key, and ca_bundle, or None if not available
        """
        if not self.certificate or not self.private_key or not self.trust_bundle:
            return None

        return {
            'cert': self.certificate,
            'key': self.private_key,
            'ca_bundle': self.trust_bundle
        }

    def has_svid(self) -> bool:
        """Check if SVID is available"""
        return self.spiffe_id is not None
