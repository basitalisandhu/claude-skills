#!/usr/bin/env python3
"""Draft an agent-threat-model system description (YAML) from a codebase.

The output follows schema/system.schema.json of https://github.com/basitalisandhu/agent-threat-model
(top-level keys system, principals, agents, channels, tools, data_stores, controls; ids match
^[a-z0-9][a-z0-9._-]*$ and are unique across element types; every reference resolves; controls are
catalogue ids). `atm validate system.yaml` accepts the draft as written; the point of the draft is that
every entry carries the files it was detected in, so a reviewer can correct it quickly.

It detects frameworks and model providers from dependency files and imports, tools by the capability
they carry (shell, messaging, database, repository writes, cloud APIs, payments, file deletion, URL fetch),
input channels (chat, e-mail, web, documents, tickets, repository issues, calendar, rules files, retrieval),
data stores, credentials, MCP servers, and signals of approvals, sandboxing, limits and a credential broker.

Usage:
  scan_agent_stack.py [ROOT] [--out system.yaml] [--json]

Standard library only. Read-only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".next", "target", "vendor", ".tox", "site-packages"}
SRC_EXTS = {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".go", ".rs", ".java", ".kt", ".cs", ".rb", ".yaml", ".yml", ".json", ".toml", ".md", ".txt", ".lock", ".cfg", ".ini"}
MAX_FILES = 4000
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

FRAMEWORKS = {
    "langchain": r"\blangchain(?:[_-]\w+)?\b", "langgraph": r"\blanggraph\b", "llamaindex": r"\bllama[_-]?index\b", "crewai": r"\bcrewai\b",
    "autogen": r"\b(autogen|pyautogen|ag2)\b", "semantic-kernel": r"\bsemantic[_-]?kernel\b", "openai-agents": r"\b(openai[_-]agents|agents\s+import\s+Agent)\b",
    "anthropic-sdk": r"\banthropic\b", "openai-sdk": r"\bopenai\b", "google-genai": r"\b(google[_.-]genai|google-generativeai|vertexai)\b",
    "mcp": r"\b(modelcontextprotocol|fastmcp|mcp\.server|from mcp\b|\"mcp\")", "vercel-ai": r"\bai/(?:core|rsc)\b|from [\"']ai[\"']|@ai-sdk/",
    "pydantic-ai": r"\bpydantic[_-]ai\b", "smolagents": r"\bsmolagents\b", "dspy": r"\bdspy\b", "haystack": r"\bhaystack\b",
    "claude-agent-sdk": r"\bclaude[_-]agent[_-]sdk\b", "bedrock-agents": r"\bbedrock[_-]agent", "litellm": r"\blitellm\b",
    "ollama": r"\bollama\b", "huggingface": r"\b(transformers|huggingface_hub)\b", "agentdojo": r"\bagentdojo\b", "browser-use": r"\bbrowser[_-]use\b",
}
PROVIDERS = {"openai": r"\b(openai|gpt-)\b", "anthropic": r"\b(anthropic|claude)\b", "google": r"\b(gemini|vertexai|google-generativeai)\b",
             "aws-bedrock": r"\bbedrock\b", "azure-openai": r"\bazure[_-]?openai\b", "mistral": r"\bmistral\b", "local": r"\b(ollama|llama\.cpp|vllm|lmstudio)\b"}

# detections keyed by the incident-dataset vocabulary (channel_in, authority); mapped to schema values in build_model
INPUT_CHANNELS = {
    "chat message": r"\b(chat|websocket|streamlit|gradio|chainlit|telegram|discord|whatsapp|twilio|teams_bot|slack_bolt|slack_sdk|@slack/bolt)\b",
    "email": r"\b(imaplib|smtplib|gmail|mailgun|sendgrid|nodemailer|imap|outlook|graph\.microsoft\.com/.*mail)\b",
    "web page": r"\b(requests\.get|httpx\.get|fetch\(|playwright|puppeteer|selenium|beautifulsoup|bs4|scrapy|readability|crawl)\b",
    "document": r"\b(pypdf|pdfplumber|docx|unstructured|textract|tika|pdf-parse|mammoth|read_text\()\b",
    "support ticket": r"\b(zendesk|freshdesk|intercom|servicenow|jira|linear\.app|helpdesk)\b",
    "repo issue/pr": r"\b(octokit|PyGithub|github\.com/repos|pull_request|issue_comment|gitlab)\b",
    "calendar invite": r"\b(googleapis\.com/calendar|calendar_v3|icalendar|ics\b|outlook.*calendar)\b",
    "package": r"\b(pip install|npm install|npx -y|uvx|pipx run)\b",
    "rules file": r"\b(CLAUDE\.md|\.cursorrules|AGENTS\.md|copilot-instructions|SKILL\.md)\b",
    "tool description": r"\b(registerTool|\.tool\(|@tool\b|function_tool|FunctionTool|StructuredTool)\b",
}
AUTHORITIES = {
    "shell/exec": r"\b(subprocess|os\.system|child_process|execSync|spawnSync|Deno\.run|exec\(|docker\.run|Popen)\b",
    "send-message": r"\b(send_email|sendmail|smtplib|sendgrid|mailgun|nodemailer|chat\.postMessage|send_message|postMessage|twilio|slack_sdk|@slack/web-api|bot\.send)\b",
    "database": r"\b(psycopg|sqlalchemy|sqlite3|pymongo|prisma|knex|sequelize|typeorm|drizzle|mysql2|pg\b|redis|supabase)\b",
    "write-repo": r"\b(git push|create_pull_request|octokit\.(rest\.)?pulls|repo\.create_|commit\(|PyGithub|simple-git)\b",
    "cloud-creds": r"\b(boto3|aws-sdk|@aws-sdk|google\.cloud|azure\.identity|@azure/|gcloud|kubernetes|kubectl|terraform)\b",
    "payments": r"\b(stripe|paypal|braintree|adyen|square|plaid|wise\.com|transfer_money|send_money)\b",
    "file-delete": r"\b(os\.remove|os\.unlink|shutil\.rmtree|fs\.(rm|unlink|rmdir)|rimraf|rm -rf)\b",
    "read-only": r"\b(read_file|readFileSync|open\(|glob|listdir|search|list_)\b",
}
DATA_STORES = {
    "vector": r"\b(pinecone|chromadb|chroma|weaviate|qdrant|faiss|milvus|pgvector|lancedb|vectorstore|VectorStore)\b",
    "relational": r"\b(postgres|postgresql|sqlite|mysql|mariadb|sqlalchemy|prisma)\b",
    "document": r"\b(mongodb|pymongo|dynamodb|firestore|cosmos)\b",
    "cache": r"\b(redis|memcached)\b",
    "object": r"\b(s3|boto3\.client\(\"s3|blob_storage|gcs|minio)\b",
    "memory": r"\b(ConversationBufferMemory|MemorySaver|mem0|zep|memory_store|long_term_memory)\b",
}
CRED_RE = re.compile(r"\b([A-Z][A-Z0-9_]{2,}(?:_API_KEY|_TOKEN|_SECRET|_PASSWORD|_CREDENTIALS|_KEY|_PAT))\b")
APPROVAL_RE = re.compile(r"(?i)\b(human[_ ]?in[_ ]?the[_ ]?loop|requires?_approval|approval|interrupt_before|confirm(ation)?|ask_user|permission)\b")
SANDBOX_RE = re.compile(r"(?i)\b(docker|firecracker|gvisor|sandbox|e2b|modal|seccomp|nsjail|bubblewrap|wasm)\b")
LIMIT_RE = re.compile(r"(?i)\b(rate[_ ]?limit|budget|max_iterations|max_turns|recursion_limit|timeout)\b")
KILL_RE = re.compile(r"(?i)\b(kill[_ ]?switch|circuit[_ ]?breaker|emergency[_ ]?stop)\b")
AUDIT_RE = re.compile(r"(?i)\b(audit[_ ]?log|audit_trail|hash[_ ]?chain)\b")
BROKER_RE = re.compile(r"\b(HISAR_URL|HISAR_AGENT_KEY|hisar-mcp|hisar_broker|hisar-broker|X-Hisar-Agent-Key)\b")

# schema vocabularies (kept in one place so the test can check against them)
CHANNEL_KINDS = {"chat", "email", "web", "document", "rag", "api", "file", "cli"}
CHANNEL_ORIGINS = {"user", "third-party", "internal"}
TOOL_KINDS = {"read", "write", "exec", "network", "payment", "messaging"}
TOOL_AUTH = {"none", "static-key", "short-lived", "brokered"}
APPROVALS = {"none", "threshold", "always"}
AUTONOMY = {"suggest", "act-with-approval", "act"}
MEMORY = {"none", "session", "persistent"}
SENSITIVITY = {"public", "internal", "confidential", "regulated"}
TRUST = {"low", "medium", "high"}
# control ids from the atm catalogue (atm catalogue controls)
CONTROL_IDS = {
    "argument-validation", "budget-caps", "egress-allowlist", "incident-response-playbook", "kill-switch", "model-version-pinning",
    "output-encoding", "prompt-injection-filtering", "rate-limiting", "secrets-out-of-context", "tool-integrity-pinning",
    "adversarial-testing", "agent-identity", "approval-fatigue-controls", "approval-gates", "audit-log", "backups-and-rollback",
    "brokered-credentials", "dlp-outbound", "input-provenance-tagging", "least-privilege-tool-scopes", "memory-write-validation",
    "per-user-authorisation", "rag-source-vetting", "runtime-policy-enforcement", "sandboxed-execution", "session-isolation",
    "behavioural-monitoring", "untrusted-content-isolation",
}

CHANNEL_MAP = {
    # detection -> (id, kind, trusted, origin, description)
    "chat message": ("chat-in", "chat", False, "user", "Chat messages from end users."),
    "email": ("email-in", "email", False, "third-party", "Inbound e-mail; anyone can send it."),
    "web page": ("web-in", "web", False, "third-party", "Web pages fetched at the model's request."),
    "document": ("documents-in", "document", False, "third-party", "Uploaded or shared documents."),
    "support ticket": ("tickets-in", "api", False, "third-party", "Support tickets written by customers."),
    "repo issue/pr": ("repo-issues-in", "api", False, "third-party", "Repository issues, pull requests and comments."),
    "calendar invite": ("calendar-in", "api", False, "third-party", "Calendar invitations and event bodies."),
    "rules file": ("rules-files", "file", False, "internal", "Instruction files in the repository; a contributor can change them."),
}
MCP_KIND_HINTS = [("filesystem", "write"), ("github", "write"), ("gitlab", "write"), ("git", "write"), ("postgres", "write"), ("sqlite", "write"),
                  ("mysql", "write"), ("mongo", "write"), ("db", "write"), ("fetch", "network"), ("browser", "network"), ("puppeteer", "network"),
                  ("playwright", "network"), ("http", "network"), ("search", "network"), ("slack", "messaging"), ("email", "messaging"),
                  ("gmail", "messaging"), ("discord", "messaging"), ("telegram", "messaging"), ("shell", "exec"), ("terminal", "exec"),
                  ("docker", "exec"), ("kube", "exec"), ("stripe", "payment"), ("pay", "payment")]


def iter_files(root: Path):
    n = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix not in SRC_EXTS or any(part in SKIP_DIRS for part in p.parts):
            continue
        n += 1
        if n > MAX_FILES:
            break
        yield p


def read(p: Path) -> str:
    try:
        if p.stat().st_size > 1_000_000:
            return ""
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def detect(root: Path) -> dict:
    hits: dict[str, dict[str, set[str]]] = {"frameworks": {}, "providers": {}, "inputs": {}, "authorities": {}, "stores": {}}
    creds: dict[str, set[str]] = {}
    mcp_servers: list[dict] = []
    signals: dict[str, set[str]] = {"approval": set(), "sandbox": set(), "limits": set(), "kill": set(), "audit": set(), "credential-broker": set()}
    files = 0
    for p in iter_files(root):
        rel = p.relative_to(root).as_posix()
        text = read(p)
        if not text:
            continue
        files += 1
        is_dep = p.name in {"requirements.txt", "pyproject.toml", "package.json", "Pipfile", "poetry.lock", "uv.lock", "package-lock.json", "go.mod", "Cargo.toml"} or p.name.startswith("requirements")
        for table, patterns in (("frameworks", FRAMEWORKS), ("providers", PROVIDERS)):
            for name, pat in patterns.items():
                if re.search(pat, text):
                    hits[table].setdefault(name, set()).add(rel)
        if is_dep or p.suffix == ".md":
            continue
        for table, patterns in (("inputs", INPUT_CHANNELS), ("authorities", AUTHORITIES), ("stores", DATA_STORES)):
            for name, pat in patterns.items():
                if re.search(pat, text):
                    hits[table].setdefault(name, set()).add(rel)
        for m in CRED_RE.finditer(text):
            creds.setdefault(m.group(1), set()).add(rel)
        for key, pat in (("approval", APPROVAL_RE), ("sandbox", SANDBOX_RE), ("limits", LIMIT_RE), ("kill", KILL_RE), ("audit", AUDIT_RE), ("credential-broker", BROKER_RE)):
            if pat.search(text):
                signals[key].add(rel)
        if p.name in {".mcp.json", "mcp.json", "claude_desktop_config.json"} or (p.name == "settings.json" and ".claude" in p.parts):
            try:
                data = json.loads(text)
                servers = data.get("mcpServers") or data.get("servers") or {}
                for sname, cfg in servers.items():
                    if isinstance(cfg, dict):
                        args = [str(a) for a in cfg.get("args", [])]
                        target = cfg.get("url") or " ".join([cfg.get("command", "")] + args)
                        pinned = bool(cfg.get("url")) or any(re.search(r"@\d|==\d|@sha256:", a) for a in args) or not any(os_base(cfg.get("command", "")) in {"npx", "uvx", "pipx", "bunx", "pnpx"} for _ in [0])
                        mcp_servers.append({"name": sname, "file": rel, "transport": cfg.get("type") or ("http" if cfg.get("url") else "stdio"),
                                            "target": target, "pinned": pinned, "has_env_secret": any(re.search(r"(?i)key|token|secret|password", k) for k in (cfg.get("env") or {}))})
            except (json.JSONDecodeError, AttributeError):
                pass
    return {"files": files, "hits": {k: {n: sorted(v)[:5] for n, v in d.items()} for k, d in hits.items()},
            "credentials": {k: sorted(v)[:3] for k, v in sorted(creds.items())}, "mcp_servers": mcp_servers,
            "signals": {k: sorted(v)[:5] for k, v in signals.items()}}


def os_base(command: str) -> str:
    return command.replace("\\", "/").rsplit("/", 1)[-1].lower()


def make_id(raw: str, taken: set[str]) -> str:
    base = re.sub(r"[^a-z0-9._-]+", "-", raw.lower()).strip("-.") or "item"
    base = re.sub(r"^[^a-z0-9]+", "", base)[:60] or "item"
    candidate, n = base, 2
    while candidate in taken:
        candidate, n = f"{base}-{n}", n + 1
    taken.add(candidate)
    return candidate


def evidence(files: list[str]) -> str:
    return "Detected in: " + ", ".join(files[:3]) if files else ""


def build_model(root: Path, d: dict) -> dict:
    """Turn detections into a dict in the agent-threat-model schema shape."""
    h, sig = d["hits"], d["signals"]
    taken: set[str] = set()
    providers = sorted(h["providers"])
    any_cred = bool(d["credentials"])
    broker = bool(sig["credential-broker"])
    default_auth = "brokered" if broker else ("static-key" if any_cred else "none")

    channels: list[dict] = []
    principal_low_channels: list[str] = []
    operator_channels: list[str] = []
    cli_id = make_id("operator-cli", taken)
    channels.append({"id": cli_id, "kind": "cli", "trusted": True, "origin": "user", "description": "Operator instructions (CLI, config, direct prompts)."})
    operator_channels.append(cli_id)
    for det, (cid, kind, trusted, origin, desc) in CHANNEL_MAP.items():
        if det in h["inputs"]:
            cid = make_id(cid, taken)
            channels.append({"id": cid, "kind": kind, "trusted": trusted, "origin": origin, "description": f"{desc} {evidence(h['inputs'][det])}".strip()})
            if origin != "internal":
                principal_low_channels.append(cid)
    stores: list[dict] = []
    store_ids: dict[str, str] = {}
    store_defs = {"vector": ("vector-store", "internal", "Embeddings and retrieved chunks."), "relational": ("relational-db", "confidential", "Application database."),
                  "document": ("document-db", "confidential", "Document database."), "cache": ("cache", "internal", "Cache or queue."),
                  "object": ("object-storage", "confidential", "Object storage bucket."), "memory": ("agent-memory", "internal", "Persistent agent memory.")}
    for det, (sid, sens, desc) in store_defs.items():
        if det in h["stores"]:
            sid = make_id(sid, taken)
            store_ids[det] = sid
            stores.append({"id": sid, "sensitivity": sens, "description": f"{desc} Set sensitivity to confidential or regulated if it holds personal data. {evidence(h['stores'][det])}".strip()})
    if "vector" in store_ids:
        rid = make_id("rag-index", taken)
        channels.append({"id": rid, "kind": "rag", "trusted": False, "origin": "internal", "description": "Retrieved chunks from the vector store; set trusted: true only if every indexed source is vetted."})
    if "write-repo" in h["authorities"]:
        sid = make_id("source-code", taken)
        store_ids["source-code"] = sid
        stores.append({"id": sid, "sensitivity": "confidential", "description": "The repository the agent can write to."})

    tools: list[dict] = []
    sandboxed = bool(sig["sandbox"])
    tool_defs = [
        ("shell/exec", "shell-exec", "exec", "host shell", "run commands on the host", {"sandboxed": sandboxed}),
        ("send-message", "send-message", "messaging", "e-mail or chat", "send messages to any recipient", {}),
        ("database", "database-access", "write", store_ids.get("relational") or store_ids.get("document") or "database", "read and write records", {}),
        ("write-repo", "repo-write", "write", store_ids.get("source-code", "repository"), "push commits and open pull requests", {}),
        ("cloud-creds", "cloud-api", "write", "cloud account", "manage cloud resources", {}),
        ("payments", "payments", "payment", "payment provider", "move money", {}),
        ("file-delete", "file-delete", "write", "filesystem", "delete files", {}),
        ("read-only", "read-files", "read", "filesystem", "read files and search", {}),
    ]
    for det, tid, kind, target, scope, extra in tool_defs:
        if det in h["authorities"]:
            tid = make_id(tid, taken)
            tool = {"id": tid, "kind": kind, "target": target, "scope": scope, "auth": default_auth if kind != "exec" else "none",
                    "approval": "none", "sandboxed": extra.get("sandboxed", False), "provider": "first-party", "pinned": True,
                    "description": evidence(h["authorities"][det])}
            if kind == "exec":
                tool["description"] = (tool["description"] + " Sandbox signals: " + (", ".join(sig["sandbox"][:3]) or "none")).strip()
            tools.append(tool)
    if "web page" in h["inputs"]:
        tid = make_id("fetch-url", taken)
        tools.append({"id": tid, "kind": "network", "target": "public internet", "scope": "fetch any URL", "auth": "none", "approval": "none",
                      "sandboxed": False, "provider": "first-party", "pinned": True, "description": "Fetches pages the model names. " + evidence(h["inputs"]["web page"])})
    for s in d["mcp_servers"]:
        kind = next((k for hint, k in MCP_KIND_HINTS if hint in s["name"].lower() or hint in s["target"].lower()), "read")
        tid = make_id(f"mcp-{s['name']}", taken)
        tools.append({"id": tid, "kind": kind, "target": s["target"], "scope": "every tool the server exposes",
                      "auth": "brokered" if "hisar-mcp" in s["target"] else ("static-key" if s["has_env_secret"] else "none"), "approval": "none",
                      "sandboxed": False, "provider": "third-party", "pinned": bool(s["pinned"]), "description": f"MCP server ({s['transport']}). Detected in: {s['file']}"})

    agent_id = make_id("main-agent", taken)
    autonomy = "act-with-approval" if (sig["approval"] or broker) else "act"
    memory = "persistent" if "memory" in store_ids else ("session" if stores else "none")
    agents = [{"id": agent_id, "model_provider": ", ".join(providers) if providers else "hosted LLM", "autonomy": autonomy, "memory": memory,
               "inputs": [c["id"] for c in channels], "tools": [t["id"] for t in tools], "model_pinned": False,
               "description": "Frameworks: " + (", ".join(sorted(h["frameworks"])) or "none detected") + ". Approval signals: " + (", ".join(sig["approval"][:3]) or "none") + "."}]

    principals = [{"id": make_id("operator", taken), "kind": "human", "trust": "high", "channels": operator_channels, "description": "Runs and configures the agent."}]
    if principal_low_channels:
        principals.append({"id": make_id("external-party", taken), "kind": "human", "trust": "low", "channels": principal_low_channels,
                           "description": "Anyone who can write to the untrusted channels."})

    controls: list[str] = []
    if sig["sandbox"] and "shell/exec" in h["authorities"]:
        controls.append("sandboxed-execution")
    if sig["limits"]:
        controls.append("rate-limiting")
    if sig["kill"] or broker:
        controls.append("kill-switch")
    if sig["audit"] or broker:
        controls.append("audit-log")
    if sig["approval"] or broker:
        controls.append("approval-gates")
    if broker:
        controls += ["brokered-credentials", "least-privilege-tool-scopes"]
    controls = [c for c in dict.fromkeys(controls) if c in CONTROL_IDS]

    return {
        "system": {"name": root.name or "system", "description": "", "owner": ""},
        "principals": principals, "agents": agents, "channels": channels, "tools": tools, "data_stores": stores, "controls": controls,
    }


# --------------------------------------------------------------------------- YAML emitter (no PyYAML)

PLAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _./@-]*$")
RESERVED = {"yes", "no", "true", "false", "null", "on", "off", "~", "y", "n"}


def scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = "" if v is None else str(v)
    if s and PLAIN_RE.match(s) and s.lower() not in RESERVED and not s.endswith(" ") and ": " not in s and " #" not in s and not re.match(r"^\d", s):
        return s
    return json.dumps(s, ensure_ascii=False)


def emit(value, indent: int = 0) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, dict):
                lines.append(f"{pad}{k}:")
                lines += emit(v, indent + 1) if v else [f"{pad}  {{}}"]
            elif isinstance(v, list):
                if not v:
                    lines.append(f"{pad}{k}: []")
                elif all(not isinstance(i, (dict, list)) for i in v):
                    lines.append(f"{pad}{k}: [" + ", ".join(scalar(i) for i in v) + "]")
                else:
                    lines.append(f"{pad}{k}:")
                    for item in v:
                        sub = emit(item, indent + 2)
                        if sub:
                            lines.append(f"{pad}  - " + sub[0].lstrip())
                            lines += sub[1:]
            else:
                lines.append(f"{pad}{k}: {scalar(v)}")
    else:
        lines.append(f"{pad}{scalar(value)}")
    return lines


HEADER = [
    "# Draft written by scan_agent_stack.py (agent-security plugin). Review every entry; descriptions name the files",
    "# each one was detected in. Fill system.description and system.owner, fix tool auth/approval/scope, set data store",
    "# sensitivity, and list the catalogue controls that are really in place (atm catalogue controls).",
    "# Format: https://github.com/basitalisandhu/agent-threat-model/blob/main/docs/input-format.md",
]


def to_yaml(model: dict) -> str:
    out = list(HEADER) + [""]
    for key in ("system", "principals", "agents", "channels", "tools", "data_stores", "controls"):
        out += emit({key: model.get(key, [] if key != "system" else {})})
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--out", help="write the YAML draft here (default: stdout)")
    ap.add_argument("--json", action="store_true", help="print the raw detections and the model as JSON instead of YAML")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    d = detect(root)
    model = build_model(root, d)
    text = json.dumps({"detections": d, "model": model}, indent=1) if args.json else to_yaml(model)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({d['files']} files scanned); next: atm validate {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
