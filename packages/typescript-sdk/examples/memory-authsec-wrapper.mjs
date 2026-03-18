#!/usr/bin/env node

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { protectedByAuthSec, runMcpServerWithOAuth } from "../dist/index.js";

const DEFAULT_AUTH_SERVICE_URL =
  "http://localhost:7468/authsec/sdkmgr/mcp-auth";
const DEFAULT_SERVICES_URL =
  "http://localhost:7468/authsec/sdkmgr/services";

function parseJsonEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`${name} must be valid JSON`);
  }
}

function sanitizeArgs(args) {
  const forwarded = { ...(args ?? {}) };
  delete forwarded.session_id;
  delete forwarded._user_info;
  return forwarded;
}

function normalizeContent(result) {
  if (result && Array.isArray(result.content)) {
    return result.content.map((item) => {
      if (item?.type === "text" && typeof item.text === "string") {
        return { type: "text", text: item.text };
      }
      return { type: "text", text: JSON.stringify(item) };
    });
  }
  return [{ type: "text", text: JSON.stringify(result) }];
}

async function main() {
  const clientId = process.env.AUTHSEC_CLIENT_ID;
  if (!clientId) {
    throw new Error("Set AUTHSEC_CLIENT_ID before running");
  }

  const host = process.env.HOST ?? "127.0.0.1";
  const port = Number(process.env.PORT ?? "3005");
  const appName =
    process.env.AUTHSEC_APP_NAME ?? `authsec-memory-wrapper-${Date.now()}`;
  const authServiceUrl =
    process.env.AUTHSEC_AUTH_SERVICE_URL ?? DEFAULT_AUTH_SERVICE_URL;
  const servicesUrl =
    process.env.AUTHSEC_SERVICES_URL ?? DEFAULT_SERVICES_URL;

  const memoryCommand = process.env.MEMORY_SERVER_COMMAND ?? "npx";
  const memoryArgs = parseJsonEnv("MEMORY_SERVER_ARGS_JSON", [
    "-y",
    "@modelcontextprotocol/server-memory",
  ]);
  const toolRoleMap = parseJsonEnv("AUTHSEC_TOOL_ROLES_JSON", {});

  const memoryEnv = { ...process.env };
  if (process.env.MEMORY_FILE_PATH) {
    memoryEnv.MEMORY_FILE_PATH = process.env.MEMORY_FILE_PATH;
  }

  const transport = new StdioClientTransport({
    command: memoryCommand,
    args: memoryArgs,
    env: memoryEnv,
    stderr: "inherit",
  });

  const memoryClient = new Client(
    { name: "authsec-memory-wrapper", version: "1.0.0" },
    { capabilities: {} }
  );

  await memoryClient.connect(transport);
  const { tools } = await memoryClient.listTools();

  const wrappedTools = tools.map((tool) =>
    protectedByAuthSec(
      {
        toolName: tool.name,
        description: `[memory] ${tool.description ?? tool.name}`,
        inputSchema: tool.inputSchema,
        roles: Array.isArray(toolRoleMap[tool.name]) ? toolRoleMap[tool.name] : [],
      },
      async (args) => {
        const result = await memoryClient.callTool({
          name: tool.name,
          arguments: sanitizeArgs(args),
        });
        return normalizeContent(result);
      }
    )
  );

  console.log("[AuthSec] Local MCP smoke test configuration");
  console.log("[AuthSec] SDK source: local dist build (../dist/index.js)");
  console.log(`[AuthSec] appName: ${appName}`);
  console.log(`[AuthSec] host: ${host}`);
  console.log(`[AuthSec] port: ${port}`);
  console.log(
    `[AuthSec] auth service: ${authServiceUrl} (${
      process.env.AUTHSEC_AUTH_SERVICE_URL ? "env override" : "sdk default"
    })`
  );
  console.log(
    `[AuthSec] services URL: ${servicesUrl} (${
      process.env.AUTHSEC_SERVICES_URL ? "env override" : "sdk default"
    })`
  );
  console.log(
    `[AuthSec] upstream memory server: ${memoryCommand} ${memoryArgs.join(" ")}`
  );

  runMcpServerWithOAuth({
    tools: wrappedTools,
    clientId,
    appName,
    host,
    port,
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
