/**
 * QuickStartSVID - Simplified SPIRE SVID integration (singleton)
 * Mirrors Python QuickStartSVID from spire_sdk.py
 *
 * Connects directly to SPIRE agent via gRPC and fetches X.509-SVIDs.
 * Provides automatic certificate renewal every 30 minutes.
 */

import * as tls from 'node:tls';
import { WorkloadAPIClient } from './workload-api-client.js';
import { WorkloadSVID } from './workload-svid.js';

export class QuickStartSVID {
  private static instance: QuickStartSVID | null = null;
  private static initPromise: Promise<QuickStartSVID> | null = null;

  private svid: WorkloadSVID | null = null;
  private grpcClient: WorkloadAPIClient | null = null;
  private renewalTimer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  private constructor() {}

  /**
   * Initialize SPIRE workload identity (singleton pattern).
   *
   * This method:
   * 1. Connects to SPIRE agent via gRPC
   * 2. Fetches X.509-SVID from agent
   * 3. Writes certificates to disk
   * 4. Starts automatic renewal (every 30 minutes)
   *
   * @param socketPath Path to SPIRE agent socket
   * @param certDir Directory to store certificates (default: /tmp/spiffe-certs)
   * @returns QuickStartSVID instance with SVID ready for mTLS
   */
  static async initialize(
    socketPath: string = '/run/spire/sockets/agent.sock',
    certDir?: string
  ): Promise<QuickStartSVID> {
    if (QuickStartSVID.instance) {
      return QuickStartSVID.instance;
    }

    // Prevent concurrent initialization
    if (QuickStartSVID.initPromise) {
      return QuickStartSVID.initPromise;
    }

    QuickStartSVID.initPromise = (async () => {
      const instance = new QuickStartSVID();
      await instance.fetch(socketPath, certDir);
      QuickStartSVID.instance = instance;
      return instance;
    })();

    try {
      return await QuickStartSVID.initPromise;
    } finally {
      QuickStartSVID.initPromise = null;
    }
  }

  /**
   * Get the singleton instance (must call initialize() first).
   */
  static async get(): Promise<QuickStartSVID> {
    if (!QuickStartSVID.instance) {
      throw new Error('Call QuickStartSVID.initialize() first');
    }
    return QuickStartSVID.instance;
  }

  private async fetch(socketPath: string, certDir?: string): Promise<void> {
    console.log('Fetching SPIFFE SVID via gRPC...');

    try {
      this.grpcClient = new WorkloadAPIClient({ socketPath });
      await this.grpcClient.connect();

      const success = await this.grpcClient.fetchX509SvidOnce();
      if (!success) {
        throw new Error('Failed to fetch SVID from agent');
      }

      this.svid = new WorkloadSVID({
        spiffeId: this.grpcClient.spiffeId!,
        certificate: this.grpcClient.certificate!,
        privateKey: this.grpcClient.privateKey!,
        trustBundle: this.grpcClient.trustBundle!,
        certDir,
      });

      console.log(`SVID initialized: ${this.svid.spiffeId}`);
      console.log('Certificates ready for mTLS');

      // Start automatic renewal (every 30 minutes)
      this.running = true;
      this.renewalTimer = setInterval(() => {
        this.renewSvid().catch((e) => {
          console.error(`SVID renewal failed: ${e.message ?? e}`);
        });
      }, 30 * 60 * 1000);

      console.log('Automatic SVID renewal enabled (30 min interval)');
    } catch (e: any) {
      console.error(`SVID initialization failed: ${e.message ?? e}`);
      throw new Error(`Failed to initialize SVID: ${e.message ?? e}`);
    }
  }

  private async renewSvid(): Promise<void> {
    if (!this.grpcClient) {
      throw new Error('gRPC client not available');
    }

    const success = await this.grpcClient.fetchX509SvidOnce();
    if (!success) {
      throw new Error('Failed to renew SVID from agent');
    }

    this.svid!.refresh(
      this.grpcClient.certificate!,
      this.grpcClient.privateKey!,
      this.grpcClient.trustBundle!
    );

    console.log('SVID renewed successfully');
  }

  /** Get SPIFFE ID */
  get spiffeId(): string {
    if (!this.svid) throw new Error('SVID not initialized');
    return this.svid.spiffeId;
  }

  /** Get certificate PEM */
  get certificate(): string {
    if (!this.svid) throw new Error('SVID not initialized');
    return this.svid.certificate;
  }

  /** Get private key PEM */
  get privateKey(): string {
    if (!this.svid) throw new Error('SVID not initialized');
    return this.svid.privateKey;
  }

  /** Get trust bundle PEM */
  get trustBundle(): string {
    if (!this.svid) throw new Error('SVID not initialized');
    return this.svid.trustBundle;
  }

  /** Get certificate file path */
  get certFilePath(): string | null {
    if (!this.svid) throw new Error('SVID not initialized');
    return this.svid.certFilePath;
  }

  /** Get private key file path */
  get keyFilePath(): string | null {
    if (!this.svid) throw new Error('SVID not initialized');
    return this.svid.keyFilePath;
  }

  /** Get CA bundle file path */
  get caFilePath(): string | null {
    if (!this.svid) throw new Error('SVID not initialized');
    return this.svid.caFilePath;
  }

  /**
   * Create TLS options for server.
   * Returns options suitable for `https.createServer(options, app)`.
   */
  createTlsOptionsForServer(): tls.SecureContextOptions & { requestCert: boolean; rejectUnauthorized: boolean } {
    if (!this.svid) throw new Error('SVID not initialized');
    return this.svid.createTlsOptionsForServer();
  }

  /**
   * Create TLS options for client.
   * Returns options suitable for `https.Agent(options)`.
   */
  createTlsOptionsForClient(): tls.SecureContextOptions & { rejectUnauthorized: boolean } {
    if (!this.svid) throw new Error('SVID not initialized');
    return this.svid.createTlsOptionsForClient();
  }

  /** Get certificate data as dict for easy passing to HTTP clients */
  getCertificateDict(): { cert: string; key: string } {
    if (!this.svid) throw new Error('SVID not initialized');
    return {
      cert: this.svid.certificate,
      key: this.svid.privateKey,
    };
  }

  /** Shutdown SVID renewal and gRPC client */
  async shutdown(): Promise<void> {
    this.running = false;

    if (this.renewalTimer) {
      clearInterval(this.renewalTimer);
      this.renewalTimer = null;
    }

    if (this.grpcClient) {
      await this.grpcClient.disconnect();
      this.grpcClient = null;
    }

    console.log('SVID renewal stopped');
  }
}
