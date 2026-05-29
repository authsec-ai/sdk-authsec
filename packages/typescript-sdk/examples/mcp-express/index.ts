/**
 * Minimal Express MCP server protected by AuthSec.
 *
 * Run:
 *   1. Register an Application in AuthSec, copy the env block from the
 *      detail page, and put it in `.env` (or export it in your shell).
 *   2. `npm install`
 *   3. `npm start`
 *
 * Unauthenticated POST /mcp returns 401 with WWW-Authenticate.
 * Authenticated POST /mcp with the right scope on the token runs the tool.
 */

import express from "express";
import { loadConfigFromEnv, mountMCP } from "@authsec/sdk";

const app = express();
app.use(express.json());

async function main() {
  const config = loadConfigFromEnv();

  await mountMCP(app, {
    config,
    path: "/mcp",
    tools: [
      {
        tool_id: "read_note",
        description: "Read a note by ID.",
        scopes_required: ["notes.read"],
      },
      {
        tool_id: "write_note",
        description: "Create or update a note.",
        scopes_required: ["notes.write"],
      },
    ],
  });

  // Your own MCP JSON-RPC handler. AuthSec has already validated the token
  // and the per-tool scope by the time this runs.
  app.post("/mcp", (req, res) => {
    const principal = (req as any).locals?.principal;
    const method = req.body?.method ?? "unknown";
    const toolName = req.body?.params?.name ?? "(none)";

    res.json({
      jsonrpc: "2.0",
      id: req.body?.id ?? null,
      result: {
        ok: true,
        actor: principal?.sub,
        method,
        tool: toolName,
        scopes: principal?.scopes ?? [],
      },
    });
  });

  const port = Number(process.env.PORT ?? 8080);
  app.listen(port, () => {
    console.log(`MCP server listening on http://localhost:${port}/mcp`);
    console.log(`Protected resource metadata at /.well-known/oauth-protected-resource/mcp`);
  });
}

main().catch((err) => {
  console.error("Failed to start:", err);
  process.exit(1);
});
