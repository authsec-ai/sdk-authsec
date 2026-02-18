/**
 * WorkloadSVID - SVID data container with certificate file management
 * Mirrors Python WorkloadSVID dataclass
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as tls from 'node:tls';

export class WorkloadSVID {
  spiffeId: string;
  certificate: string;
  privateKey: string;
  trustBundle: string;
  certDir: string;

  certFilePath: string | null = null;
  keyFilePath: string | null = null;
  caFilePath: string | null = null;

  constructor(options: {
    spiffeId: string;
    certificate: string;
    privateKey: string;
    trustBundle: string;
    certDir?: string;
  }) {
    this.spiffeId = options.spiffeId;
    this.certificate = options.certificate;
    this.privateKey = options.privateKey;
    this.trustBundle = options.trustBundle;
    this.certDir = options.certDir ?? path.join(os.tmpdir(), 'spiffe-certs');

    this.writeCertsToFiles();
  }

  /** Write certificates to persistent files for mTLS */
  private writeCertsToFiles(): void {
    fs.mkdirSync(this.certDir, { recursive: true });

    if (!this.certFilePath) {
      this.certFilePath = path.join(this.certDir, 'svid.crt');
      this.keyFilePath = path.join(this.certDir, 'svid.key');
      this.caFilePath = path.join(this.certDir, 'ca.crt');
    }

    this.atomicWrite(this.certFilePath, this.certificate);
    this.atomicWrite(this.keyFilePath!, this.privateKey);
    this.atomicWrite(this.caFilePath!, this.trustBundle);

    // Set restrictive permissions on private key
    fs.chmodSync(this.keyFilePath!, 0o600);

    console.log('Certificates written to disk:');
    console.log(`  Cert: ${this.certFilePath}`);
    console.log(`  Key: ${this.keyFilePath}`);
    console.log(`  CA: ${this.caFilePath}`);
  }

  /** Atomically write content to file */
  private atomicWrite(filePath: string, content: string): void {
    const tempPath = filePath + '.tmp';
    try {
      fs.writeFileSync(tempPath, content, { encoding: 'utf-8', flush: true });
      fs.renameSync(tempPath, filePath);
    } catch (e) {
      try {
        fs.unlinkSync(tempPath);
      } catch {
        // ignore cleanup error
      }
      throw e;
    }
  }

  /**
   * Create TLS options for server (e.g., Express HTTPS).
   * Returns options suitable for `https.createServer(options, app)`.
   */
  createTlsOptionsForServer(): tls.SecureContextOptions & { requestCert: boolean; rejectUnauthorized: boolean } {
    if (!this.certFilePath || !this.keyFilePath || !this.caFilePath) {
      throw new Error('Certificates not initialized');
    }

    return {
      cert: fs.readFileSync(this.certFilePath, 'utf-8'),
      key: fs.readFileSync(this.keyFilePath, 'utf-8'),
      ca: fs.readFileSync(this.caFilePath, 'utf-8'),
      requestCert: true,
      rejectUnauthorized: true,
    };
  }

  /**
   * Create TLS options for client (e.g., fetch with custom agent).
   * Returns options suitable for `https.Agent(options)`.
   */
  createTlsOptionsForClient(): tls.SecureContextOptions & { rejectUnauthorized: boolean } {
    if (!this.certFilePath || !this.keyFilePath || !this.caFilePath) {
      throw new Error('Certificates not initialized');
    }

    return {
      cert: fs.readFileSync(this.certFilePath, 'utf-8'),
      key: fs.readFileSync(this.keyFilePath, 'utf-8'),
      ca: fs.readFileSync(this.caFilePath, 'utf-8'),
      rejectUnauthorized: true,
    };
  }

  /** Refresh SVID data (called during renewal) */
  refresh(certificate: string, privateKey: string, trustBundle: string): void {
    this.certificate = certificate;
    this.privateKey = privateKey;
    this.trustBundle = trustBundle;
    this.writeCertsToFiles();
    console.log(`SVID refreshed: ${this.spiffeId}`);
  }
}
