#!/usr/bin/env node

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { protectedByAuthSec, runMcpServerWithOAuth } from "../dist/index.js";

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

  const appName =
    process.env.AUTHSEC_APP_NAME ?? `authsec-memory-wrapper-${Date.now()}`;
  console.log(`[AuthSec] appName: ${appName}`);

  runMcpServerWithOAuth({
    tools: wrappedTools,
    clientId,
    appName,
    host: process.env.HOST ?? "127.0.0.1",
    port: Number(process.env.PORT ?? "3005"),
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
