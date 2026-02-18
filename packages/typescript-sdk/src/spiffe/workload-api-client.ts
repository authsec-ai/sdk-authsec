/**
 * SPIFFE Workload API - gRPC Client
 * Mirrors Python WorkloadAPIClient
 *
 * Client library for workloads to fetch SVIDs from the gRPC Workload API.
 * Supports streaming X.509-SVIDs with automatic rotation.
 */

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as path from 'node:path';

// Load proto definition at runtime
// __dirname works in CJS; for ESM, users would need to set AUTHSEC_PROTO_PATH
const PROTO_PATH =
  process.env.AUTHSEC_PROTO_PATH ??
  path.join(__dirname, 'proto', 'workload.proto');

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

const protoDescriptor = grpc.loadPackageDefinition(packageDefinition) as any;
const SpiffeWorkloadAPIService =
  protoDescriptor.spiffe.workload.SpiffeWorkloadAPI;

export class WorkloadAPIClient {
  private socketPath: string;
  private logger: { info: Function; error: Function; debug: Function };

  // Current SVID data
  spiffeId: string | null = null;
  certificate: string | null = null;
  privateKey: string | null = null;
  trustBundle: string | null = null;

  // gRPC client
  private client: any = null;
  private streamCall: any = null;
  private running = false;

  constructor(options?: {
    socketPath?: string;
    logger?: { info: Function; error: Function; debug: Function };
  }) {
    this.socketPath =
      options?.socketPath ?? '/tmp/spire-agent/public/api.sock';
    this.logger = options?.logger ?? {
      info: console.log,
      error: console.error,
      debug: () => {},
    };
  }

  /** Connect to the Workload API */
  async connect(): Promise<void> {
    this.logger.info('Connecting to gRPC Workload API');
    this.logger.info(`  Socket: ${this.socketPath}`);

    let target: string;

    if (this.socketPath.startsWith('tcp://')) {
      // TCP socket (Windows, VMs, K8s service endpoints)
      target = this.socketPath.replace('tcp://', '');
      this.logger.info(`  Using TCP socket: ${target}`);
    } else if (this.socketPath.startsWith('unix://')) {
      // Unix socket with unix:// prefix
      const unixPath = this.socketPath.replace('unix://', '');
      target = `unix:${unixPath}`;
      this.logger.info(`  Using Unix socket: ${unixPath}`);
    } else {
      // Standard Unix socket path
      target = `unix:${this.socketPath}`;
      this.logger.info('  Using Unix socket');
    }

    this.client = new SpiffeWorkloadAPIService(
      target,
      grpc.credentials.createInsecure()
    );

    this.logger.info('Connected to Workload API');
  }

  /** Disconnect from Workload API */
  async disconnect(): Promise<void> {
    this.running = false;

    if (this.streamCall) {
      this.streamCall.cancel();
      this.streamCall = null;
    }

    if (this.client) {
      this.client.close();
      this.client = null;
    }

    this.logger.info('Disconnected from Workload API');
  }

  /** Build gRPC metadata from environment variables */
  private buildMetadata(): grpc.Metadata {
    const metadata = new grpc.Metadata();

    // For TCP sockets, send PID
    if (this.socketPath.startsWith('tcp://')) {
      metadata.set('x-pid', String(process.pid));
      this.logger.debug(`Sending PID ${process.pid} in gRPC metadata`);
    }

    // Kubernetes metadata
    const k8sVars: Array<[string, string]> = [
      ['POD_NAMESPACE', 'x-k8s-namespace'],
      ['POD_NAME', 'x-k8s-pod-name'],
      ['POD_UID', 'x-k8s-pod-uid'],
      ['SERVICE_ACCOUNT', 'x-k8s-service-account'],
      ['POD_LABEL_APP', 'x-k8s-pod-label-app'],
    ];

    for (const [envVar, metaKey] of k8sVars) {
      const value = process.env[envVar];
      if (value) {
        metadata.set(metaKey, value);
        this.logger.debug(`Sending ${metaKey}: ${value}`);
      }
    }

    // Docker metadata
    const dockerVars: Array<[string, string]> = [
      ['DOCKER_CONTAINER_ID', 'x-docker-container-id'],
      ['DOCKER_CONTAINER_NAME', 'x-docker-container-name'],
      ['DOCKER_IMAGE_NAME', 'x-docker-image-name'],
    ];

    for (const [envVar, metaKey] of dockerVars) {
      const value = process.env[envVar];
      if (value) {
        metadata.set(metaKey, value);
        this.logger.debug(`Sending ${metaKey}: ${value}`);
      }
    }

    // Docker labels as metadata (prefixed with DOCKER_LABEL_)
    for (const [key, value] of Object.entries(process.env)) {
      if (key.startsWith('DOCKER_LABEL_') && value) {
        const labelName = key.slice('DOCKER_LABEL_'.length).toLowerCase();
        metadata.set(`x-docker-label-${labelName}`, value);
        this.logger.debug(`Sending Docker label ${labelName}: ${value}`);
      }
    }

    return metadata;
  }

  /**
   * Fetch X.509-SVID once (single request/response).
   * @returns true if successful, false otherwise
   */
  async fetchX509SvidOnce(): Promise<boolean> {
    try {
      if (!this.client) {
        await this.connect();
      }

      const metadata = this.buildMetadata();

      return new Promise<boolean>((resolve) => {
        const stream = this.client.FetchX509SVID({}, metadata);

        stream.on('data', (response: any) => {
          if (response.svids && response.svids.length > 0) {
            const svid = response.svids[0];
            this.spiffeId = svid.spiffe_id;
            this.certificate =
              typeof svid.x509_svid === 'string'
                ? svid.x509_svid
                : Buffer.from(svid.x509_svid).toString('utf-8');
            this.privateKey =
              typeof svid.x509_svid_key === 'string'
                ? svid.x509_svid_key
                : Buffer.from(svid.x509_svid_key).toString('utf-8');
            this.trustBundle =
              typeof svid.bundle === 'string'
                ? svid.bundle
                : Buffer.from(svid.bundle).toString('utf-8');

            this.logger.info('Fetched X.509-SVID');
            this.logger.info(`  SPIFFE ID: ${this.spiffeId}`);
            this.logger.info('  Certificate issued and ready to use');
            this.logger.info('  Trust Bundle received from agent');

            stream.cancel();
            resolve(true);
          } else {
            this.logger.error('No SVIDs in response');
            stream.cancel();
            resolve(false);
          }
        });

        stream.on('error', (err: any) => {
          if (err.code !== grpc.status.CANCELLED) {
            this.logger.error(
              `gRPC error fetching SVID: ${err.code} - ${err.details ?? err.message}`
            );
          }
          resolve(false);
        });
      });
    } catch (e: any) {
      this.logger.error(`Failed to fetch SVID: ${e.message ?? e}`);
      return false;
    }
  }

  /**
   * Start streaming X.509-SVID updates.
   * @param onUpdate Optional callback called when SVID is updated
   */
  async startStreaming(
    onUpdate?: (client: WorkloadAPIClient) => Promise<void>
  ): Promise<void> {
    this.running = true;

    if (!this.client) {
      await this.connect();
    }

    this.logger.info('Starting X.509-SVID stream...');

    const metadata = this.buildMetadata();
    this.streamCall = this.client.FetchX509SVID({}, metadata);

    this.streamCall.on('data', async (response: any) => {
      if (!this.running) return;

      if (response.svids && response.svids.length > 0) {
        const svid = response.svids[0];
        this.spiffeId = svid.spiffe_id;
        this.certificate =
          typeof svid.x509_svid === 'string'
            ? svid.x509_svid
            : Buffer.from(svid.x509_svid).toString('utf-8');
        this.privateKey =
          typeof svid.x509_svid_key === 'string'
            ? svid.x509_svid_key
            : Buffer.from(svid.x509_svid_key).toString('utf-8');
        this.trustBundle =
          typeof svid.bundle === 'string'
            ? svid.bundle
            : Buffer.from(svid.bundle).toString('utf-8');

        this.logger.info('Received SVID update');
        this.logger.info(`  SPIFFE ID: ${this.spiffeId}`);
        this.logger.info('  Certificate refreshed from agent');
        this.logger.info('  Trust Bundle updated');

        if (onUpdate) {
          await onUpdate(this);
        }
      }
    });

    this.streamCall.on('error', (err: any) => {
      if (err.code !== grpc.status.CANCELLED) {
        this.logger.error(
          `gRPC stream error: ${err.code} - ${err.details ?? err.message}`
        );
      }
    });

    this.streamCall.on('end', () => {
      this.logger.info('SVID stream ended');
    });
  }

  /**
   * Fetch JWT-SVID.
   * @param audience List of audiences for the JWT
   * @param spiffeId Optional SPIFFE ID (defaults to workload's identity)
   * @returns JWT token or null
   */
  async fetchJwtSvid(
    audience: string[],
    spiffeId?: string
  ): Promise<string | null> {
    try {
      if (!this.client) {
        await this.connect();
      }

      return new Promise<string | null>((resolve) => {
        this.client.FetchJWTSVID(
          { audience, spiffe_id: spiffeId ?? '' },
          (err: any, response: any) => {
            if (err) {
              this.logger.error(
                `gRPC error fetching JWT-SVID: ${err.code} - ${err.details ?? err.message}`
              );
              resolve(null);
              return;
            }

            if (response.svids && response.svids.length > 0) {
              const jwtSvid = response.svids[0];
              this.logger.info('Fetched JWT-SVID');
              this.logger.info(`  SPIFFE ID: ${jwtSvid.spiffe_id}`);
              this.logger.info(`  Audience: ${audience}`);
              resolve(jwtSvid.svid);
            } else {
              this.logger.error('No JWT-SVIDs in response');
              resolve(null);
            }
          }
        );
      });
    } catch (e: any) {
      this.logger.error(`Failed to fetch JWT-SVID: ${e.message ?? e}`);
      return null;
    }
  }

  /**
   * Validate JWT-SVID.
   * @param token JWT token to validate
   * @param audience Expected audience
   * @returns Validation result with spiffe_id and claims, or null if invalid
   */
  async validateJwtSvid(
    token: string,
    audience: string
  ): Promise<{ spiffeId: string; claims: Record<string, string> } | null> {
    try {
      if (!this.client) {
        await this.connect();
      }

      return new Promise((resolve) => {
        this.client.ValidateJWTSVID(
          { svid: token, audience },
          (err: any, response: any) => {
            if (err) {
              this.logger.error(
                `gRPC error validating JWT-SVID: ${err.code} - ${err.details ?? err.message}`
              );
              resolve(null);
              return;
            }

            this.logger.info('JWT-SVID validated');
            this.logger.info(`  SPIFFE ID: ${response.spiffe_id}`);

            resolve({
              spiffeId: response.spiffe_id,
              claims: response.claims ?? {},
            });
          }
        );
      });
    } catch (e: any) {
      this.logger.error(`Failed to validate JWT-SVID: ${e.message ?? e}`);
      return null;
    }
  }

  /**
   * Get mTLS configuration for HTTP clients.
   * @returns Object with cert, key, and caBundle, or null if not available
   */
  getMtlsConfig(): {
    cert: string;
    key: string;
    caBundle: string;
  } | null {
    if (!this.certificate || !this.privateKey || !this.trustBundle) {
      return null;
    }

    return {
      cert: this.certificate,
      key: this.privateKey,
      caBundle: this.trustBundle,
    };
  }

  /** Check if SVID is available */
  hasSvid(): boolean {
    return this.spiffeId !== null;
  }
}
