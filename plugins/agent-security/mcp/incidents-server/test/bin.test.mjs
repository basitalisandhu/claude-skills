import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SERVER_NAME } from "../dist/index.js";

// npm installs a bin as a symlink to dist/index.js; the server must still start when run that way.
test("starts on stdio when run through a symlinked bin", async () => {
  const dir = mkdtempSync(join(tmpdir(), "agent-incidents-bin-"));
  const link = join(dir, "agent-incidents-mcp");
  symlinkSync(fileURLToPath(new URL("../dist/index.js", import.meta.url)), link);
  const client = new Client({ name: "bin-test", version: "0.0.0" });
  try {
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [link], stderr: "ignore" }));
    assert.equal(client.getServerVersion()?.name, SERVER_NAME);
    const { tools } = await client.listTools();
    assert.ok(tools.length > 0);
  } finally {
    await client.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// prepack adds data/incidents.json at publish time; it is skipped here so parallel tests never see that copy.
test("npm pack ships dist and server.json, not the sources", async () => {
  const { execFileSync } = await import("node:child_process");
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const out = execFileSync(npm, ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: fileURLToPath(new URL("..", import.meta.url)), encoding: "utf8" });
  const files = JSON.parse(out)[0].files.map((f) => f.path);
  assert.ok(files.includes("dist/index.js"));
  assert.ok(files.includes("server.json"));
  assert.ok(!files.some((f) => f.startsWith("src/") || f.startsWith("test/")));
});
