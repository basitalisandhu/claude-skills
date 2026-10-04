import { test } from "node:test";
import assert from "node:assert/strict";
import { loadDataset, parseDataset, searchIncidents, getIncident, stats, defaultDataPath, primaryUrl } from "../dist/data.js";

const ds = loadDataset();

test("bundled dataset is the published array shape", () => {
  assert.match(defaultDataPath(), /plugins[\\/]agent-security[\\/]data[\\/]incidents\.json$/);
  assert.ok(ds.count >= 80);
  assert.equal(ds.count, ds.incidents.length);
  assert.ok(ds.fields.vector.includes("indirect-injection"));
  assert.ok(ds.fields.owasp_agentic.includes("ASI01"));
  for (const i of ds.incidents) {
    assert.match(i.id, /^\d{3,}$/);
    assert.match(i.date, /^\d{4}-\d{2}(-\d{2})?$/);
    assert.ok(Array.isArray(i.cve));
    assert.ok(primaryUrl(i).startsWith("https://"), `${i.id} has no primary source`);
    assert.ok(Array.isArray(i.mappings.owasp_agentic) && Array.isArray(i.affected.vendors) && Array.isArray(i.tags));
    assert.ok(["confirmed", "reported", "disputed"].includes(i.status));
  }
});

test("search filters combine and are case-insensitive", () => {
  const r = searchIncidents(ds, { vector: "Indirect-Injection", authority: "shell/exec" });
  assert.ok(r.total > 0);
  for (const i of r.incidents) {
    assert.equal(i.vector, "indirect-injection");
    assert.equal(i.authority, "shell/exec");
  }
  const dates = r.incidents.map((i) => i.date);
  assert.deepEqual(dates, [...dates].sort().reverse());
});

test("search supports vendor, mapping, tag, query, date range, cve_only and limit", () => {
  assert.ok(searchIncidents(ds, { vendor: "cursor" }).total >= 3);
  const asi = searchIncidents(ds, { owasp_agentic: "ASI01", limit: 100 });
  assert.ok(asi.total > 0);
  for (const i of asi.incidents) assert.ok(i.mappings.owasp_agentic.includes("ASI01"));
  assert.ok(searchIncidents(ds, { mitre_atlas: "AML.T0051.000" }).total > 0);
  assert.ok(searchIncidents(ds, { tag: "chatbot" }).total > 0);
  assert.ok(searchIncidents(ds, { framework: "langchain" }).total > 0);
  const mcp = searchIncidents(ds, { query: "mcp", limit: 2 });
  assert.equal(mcp.incidents.length, 2);
  assert.ok(mcp.total > 2);
  const y2025 = searchIncidents(ds, { since: "2025-01", until: "2025-12", cve_only: true, limit: 100 });
  for (const i of y2025.incidents) {
    assert.ok(i.date.slice(0, 7) >= "2025-01" && i.date.slice(0, 7) <= "2025-12");
    assert.ok(i.cve.length > 0);
  }
  assert.equal(searchIncidents(ds, { vector: "no-such-vector" }).total, 0);
});

test("get_incident accepts padded and unpadded ids", () => {
  assert.equal(getIncident(ds, "030")?.id, "030");
  assert.equal(getIncident(ds, "30")?.id, "030");
  assert.equal(getIncident(ds, "999"), undefined);
});

test("stats sums to the filtered total, including list fields", () => {
  const s = stats(ds, "outcome");
  assert.equal(s.total, ds.count);
  assert.equal(s.rows.reduce((n, r) => n + r.count, 0), ds.count);
  const filtered = stats(ds, "year", { vector: "supply-chain" });
  assert.equal(filtered.total, searchIncidents(ds, { vector: "supply-chain", limit: 100 }).total);
  assert.ok(stats(ds, "vendor").rows.some((r) => r.value === "OpenAI"));
  assert.ok(stats(ds, "owasp_agentic").rows.some((r) => r.value === "ASI01"));
  assert.ok(stats(ds, "status").rows.some((r) => r.value === "confirmed"));
});

test("parseDataset accepts the schema shape and the legacy flat shape", () => {
  const parsed = parseDataset(JSON.stringify([
    { id: "001", date: "2026-01", name: "x", vector: "poisoning", adversarial: true, cve: ["CVE-2026-1"], sources: [{ url: "https://e.x/a" }], summary: "s",
      mappings: { owasp_agentic: ["ASI04"], owasp_llm: [], mitre_atlas: [] }, affected: { vendors: ["Acme"], products: [], frameworks: [] }, tags: ["t"], status: "confirmed" },
    { id: "7", date: "2026-02", name: "legacy", vector: "poisoning", adversarial: "yes", cve: "-", url: "https://e.x/b", notes: "n", vendors: ["Old"] },
  ]));
  assert.equal(parsed.count, 2);
  const legacy = parsed.incidents.find((i) => i.id === "7");
  assert.equal(legacy.adversarial, true);
  assert.deepEqual(legacy.cve, []);
  assert.equal(primaryUrl(legacy), "https://e.x/b");
  assert.equal(legacy.summary, "n");
  assert.deepEqual(legacy.affected.vendors, ["Old"]);
  assert.throws(() => parseDataset("{}"), /incidents array/);
  assert.throws(() => parseDataset("[]"), /empty/);
});
