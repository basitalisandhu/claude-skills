import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer, SERVER_NAME } from "../dist/index.js";

async function connected() {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createServer();
  await server.connect(serverTransport);
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await client.connect(clientTransport);
  return { client, server };
}

const parse = (result) => JSON.parse(result.content[0].text);

test("server exposes exactly the three documented read-only tools", async () => {
  const { client, server } = await connected();
  try {
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), ["get_incident", "search_incidents", "stats"]);
    for (const t of tools) {
      assert.equal(t.annotations?.readOnlyHint, true, `${t.name} must be read-only`);
      assert.equal(t.annotations?.openWorldHint, false);
    }
    assert.equal(client.getServerVersion()?.name, SERVER_NAME);
    assert.match(client.getInstructions() ?? "", /ASI01/);
  } finally {
    await client.close();
    await server.close();
  }
});

test("search_incidents, get_incident and stats round-trip over MCP", async () => {
  const { client, server } = await connected();
  try {
    const search = parse(await client.callTool({ name: "search_incidents", arguments: { vector: "indirect-injection", channel_in: "repo issue/pr", limit: 5 } }));
    assert.ok(search.total >= 1);
    assert.ok(search.returned <= 5);
    for (const i of search.incidents) {
      assert.equal(i.vector, "indirect-injection");
      assert.ok(i.primary_source.startsWith("https://"));
      assert.ok(Array.isArray(i.mappings.owasp_agentic));
    }
    const byMapping = parse(await client.callTool({ name: "search_incidents", arguments: { owasp_agentic: "ASI05", limit: 3 } }));
    assert.ok(byMapping.total >= 1);

    const one = parse(await client.callTool({ name: "get_incident", arguments: { id: "30" } }));
    assert.equal(one.id, "030");
    assert.match(one.name, /GitHub MCP/);
    assert.ok(one.summary.length > 10);
    assert.ok(one.sources.length >= 1);
    assert.ok(one.affected.vendors.length >= 1);

    const missing = await client.callTool({ name: "get_incident", arguments: { id: "nope" } });
    assert.equal(missing.isError, true);

    const st = parse(await client.callTool({ name: "stats", arguments: { by: "owasp_agentic", since: "2025-01" } }));
    assert.equal(st.by, "owasp_agentic");
    assert.ok(st.rows.some((r) => r.value === "ASI01"));
    const dflt = parse(await client.callTool({ name: "stats", arguments: {} }));
    assert.equal(dflt.by, "vector");
    assert.equal(dflt.rows.reduce((n, r) => n + r.count, 0), dflt.total);
  } finally {
    await client.close();
    await server.close();
  }
});

test("invalid arguments are rejected by the schema", async () => {
  const { client, server } = await connected();
  try {
    const bad = await client.callTool({ name: "search_incidents", arguments: { since: "2025" } });
    assert.equal(bad.isError, true);
    const badId = await client.callTool({ name: "search_incidents", arguments: { owasp_agentic: "ASI99" } });
    assert.equal(badId.isError, true);
  } finally {
    await client.close();
    await server.close();
  }
});
