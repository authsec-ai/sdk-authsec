#!/usr/bin/env node
/**
 * AuthSec CLI — interactive setup for .authsec.json configuration.
 *
 * Usage:
 *   authsec init          Interactive URL + client_id setup
 *   authsec config show   Display current saved configuration
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';

const CONFIG_FILE = '.authsec.json';

const DEFAULTS = {
  auth_service_url: 'https://dev.api.authsec.dev/authsec/sdkmgr/mcp-auth',
  services_base_url: 'https://dev.api.authsec.dev/authsec/sdkmgr/services',
  ciba_base_url: 'https://dev.api.authsec.dev',
};

function configPath(): string {
  return path.join(process.cwd(), CONFIG_FILE);
}

function prompt(rl: readline.Interface, message: string, defaultValue?: string): Promise<string> {
  return new Promise((resolve) => {
    const suffix = defaultValue ? ` [${defaultValue}]: ` : ': ';
    rl.question(message + suffix, (answer) => {
      const trimmed = answer.trim();
      if (trimmed) {
        resolve(trimmed);
      } else if (defaultValue) {
        resolve(defaultValue);
      } else {
        // Required field — ask again
        console.log('  This field is required.');
        resolve(prompt(rl, message, defaultValue) as unknown as string);
      }
    });
  });
}

async function cmdInit(): Promise<void> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  console.log('AuthSec SDK — interactive setup\n');

  const choice = await prompt(rl, 'Use default AuthSec URLs or custom? (default/custom)', 'default');

  let authServiceUrl: string;
  let servicesBaseUrl: string;
  let cibaBaseUrl: string;

  if (choice.toLowerCase().startsWith('c')) {
    authServiceUrl = await prompt(rl, 'Auth Service URL', DEFAULTS.auth_service_url);
    servicesBaseUrl = await prompt(rl, 'Services Base URL', DEFAULTS.services_base_url);
    cibaBaseUrl = await prompt(rl, 'CIBA Base URL', DEFAULTS.ciba_base_url);
  } else {
    authServiceUrl = DEFAULTS.auth_service_url;
    servicesBaseUrl = DEFAULTS.services_base_url;
    cibaBaseUrl = DEFAULTS.ciba_base_url;
  }

  const clientId = await prompt(rl, 'client_id (required)');

  rl.close();

  const config = {
    client_id: clientId,
    auth_service_url: authServiceUrl,
    services_base_url: servicesBaseUrl,
    ciba_base_url: cibaBaseUrl,
  };

  const cfgPath = configPath();
  fs.writeFileSync(cfgPath, JSON.stringify(config, null, 2) + '\n');

  console.log(`\nConfig saved to ${cfgPath}\n`);
  printConfig(config);
}

function cmdConfigShow(): void {
  const cfgPath = configPath();
  if (!fs.existsSync(cfgPath)) {
    console.log(`No config file found at ${cfgPath}`);
    console.log("Run 'authsec init' to create one.");
    process.exit(1);
  }

  const config = JSON.parse(fs.readFileSync(cfgPath, 'utf-8'));
  printConfig(config);
}

function printConfig(config: Record<string, string>): void {
  console.log('Current AuthSec configuration:');
  for (const [key, value] of Object.entries(config)) {
    console.log(`  ${key}: ${value}`);
  }
}

function printHelp(): void {
  console.log(
    'AuthSec CLI — interactive setup for .authsec.json configuration.\n\n' +
      'Usage:\n' +
      '  authsec init          Interactive URL + client_id setup\n' +
      '  authsec config show   Display current saved configuration',
  );
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    printHelp();
    process.exit(0);
  }

  const command = args[0];

  if (command === 'init') {
    await cmdInit();
  } else if (command === 'config' && args[1] === 'show') {
    cmdConfigShow();
  } else {
    console.log(`Unknown command: ${args.join(' ')}`);
    printHelp();
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
