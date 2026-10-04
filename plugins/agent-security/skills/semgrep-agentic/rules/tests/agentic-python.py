import os
import pickle
import subprocess

import requests
import torch
from langchain_core.tools import tool
from mcp.server.fastmcp import FastMCP


def run_generated(client, prompt):
    resp = client.chat.completions.create(model="m", messages=[{"role": "user", "content": prompt}])
    code = resp.choices[0].message.content
    # ruleid: agentic.python.model-output-to-exec
    exec(code)
    # ruleid: agentic.python.model-output-to-exec
    subprocess.run(code, shell=True)


def run_anthropic(client, prompt):
    msg = client.messages.create(model="m", max_tokens=10, messages=[{"role": "user", "content": prompt}])
    cmd = msg.content[0].text
    # ruleid: agentic.python.model-output-to-exec
    os.system(cmd)


def safe_exec():
    static = "print('hello')"
    # ok: agentic.python.model-output-to-exec
    exec(static)


def shell_calls(name):
    # ruleid: agentic.python.shell-true-with-interpolation
    subprocess.run(f"ls {name}", shell=True)
    # ruleid: agentic.python.shell-true-with-interpolation
    subprocess.check_output("ls %s" % name, shell=True)
    # ruleid: agentic.python.shell-true-with-interpolation
    os.system("cat " + name)
    # ok: agentic.python.shell-true-with-interpolation
    subprocess.run(["ls", name])
    # ok: agentic.python.shell-true-with-interpolation
    subprocess.run("ls", shell=True)


def prompts(client, user_text, docs):
    # ruleid: agentic.python.user-input-in-system-prompt
    messages = [{"role": "system", "content": f"You are a helper. Context: {docs}"}]
    # ruleid: agentic.python.user-input-in-system-prompt
    client.messages.create(model="m", max_tokens=1, system="Rules: " + user_text, messages=[])
    # ok: agentic.python.user-input-in-system-prompt
    messages2 = [{"role": "system", "content": "You are a helper."}, {"role": "user", "content": f"Context: {docs}"}]
    return messages, messages2


@tool
def fetch_page(url: str) -> str:
    """Fetch a page."""
    # ruleid: agentic.python.tool-fetches-model-controlled-url
    return requests.get(url, timeout=5).text


mcp = FastMCP("demo")


@mcp.tool()
def fetch_json(endpoint: str) -> dict:
    # ruleid: agentic.python.tool-fetches-model-controlled-url
    return requests.get(endpoint).json()


@mcp.tool()
def fetch_fixed() -> dict:
    # ok: agentic.python.tool-fetches-model-controlled-url
    return requests.get("https://api.example.com/status").json()


def plain_fetch(url):
    # ok: agentic.python.tool-fetches-model-controlled-url
    return requests.get(url)


def serve(app):
    # ruleid: agentic.python.mcp-server-binds-all-interfaces
    app.run(host="0.0.0.0", port=8000)
    # ruleid: agentic.python.mcp-server-binds-all-interfaces
    mcp.run(transport="sse", host="0.0.0.0")
    # ok: agentic.python.mcp-server-binds-all-interfaces
    app.run(host="127.0.0.1", port=8000)


def load_models(path):
    # ruleid: agentic.python.pickle-model-load
    model = pickle.load(open(path, "rb"))
    # ruleid: agentic.python.pickle-model-load
    weights = torch.load(path)
    # ok: agentic.python.pickle-model-load
    safe = torch.load(path, weights_only=True)
    return model, weights, safe
