import { exec, execSync } from "node:child_process";
import OpenAI from "openai";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import express from "express";

const client = new OpenAI();

async function runGenerated(prompt: string) {
  const completion = await client.chat.completions.create({ model: "m", messages: [{ role: "user", content: prompt }] });
  const code = completion.choices[0].message.content ?? "";
  // ruleid: agentic.js.model-output-to-exec
  eval(code);
  // ruleid: agentic.js.model-output-to-exec
  execSync(code);
}

function staticExec() {
  const code = "console.log(1)";
  // ok: agentic.js.model-output-to-exec
  eval(code);
}

function shell(name: string) {
  // ruleid: agentic.js.exec-with-template-literal
  exec(`ls ${name}`);
  // ruleid: agentic.js.exec-with-template-literal
  execSync("cat " + name);
  // ok: agentic.js.exec-with-template-literal
  execSync("ls");
}

function prompts(userText: string, docs: string) {
  // ruleid: agentic.js.user-input-in-system-prompt
  const messages = [{ role: "system", content: `You are a helper. Context: ${docs}` }];
  // ruleid: agentic.js.user-input-in-system-prompt
  const messages2 = [{ role: "system", content: "Rules: " + userText }];
  // ok: agentic.js.user-input-in-system-prompt
  const messages3 = [{ role: "system", content: "You are a helper." }, { role: "user", content: `Context: ${docs}` }];
  return [messages, messages2, messages3];
}

const server = new McpServer({ name: "demo", version: "0" });

server.registerTool("fetch_page", { description: "fetch" }, async ({ url }) => {
  // ruleid: agentic.js.tool-fetches-model-controlled-url
  const res = await fetch(url);
  return { content: [{ type: "text", text: await res.text() }] };
});

server.registerTool("status", { description: "status" }, async () => {
  // ok: agentic.js.tool-fetches-model-controlled-url
  const res = await fetch("https://api.example.com/status");
  return { content: [{ type: "text", text: await res.text() }] };
});

function listen() {
  const app = express();
  // ruleid: agentic.js.mcp-server-binds-all-interfaces
  app.listen(3000, "0.0.0.0");
  // ok: agentic.js.mcp-server-binds-all-interfaces
  app.listen(3000, "127.0.0.1");
}
