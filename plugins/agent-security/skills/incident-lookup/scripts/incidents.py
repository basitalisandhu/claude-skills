#!/usr/bin/env python3
"""Query the AI agent incident dataset (https://github.com/basitalisandhu/ai-agent-incidents).

Records follow schema/incident.schema.json of that repository: the eight coded fields (type, lens, vector,
channel_in, authority, channel_out, adversarial, outcome), identifiers (id, date, name, cve[], sources[], summary),
and the added fields mappings{owasp_agentic, owasp_llm, mitre_atlas}, affected{vendors, products, frameworks},
tags[] and status. The bundled snapshot is a copy of the published site/incidents.json, so online and offline
results have the same shape.

Data sources, in order:
  1. --data FILE          an explicit JSON file (array of records, or an object with an "incidents" array)
  2. local cache (24 h)   $XDG_CACHE_HOME/agent-security-skills/incidents.json or ~/.cache/...
  3. the published file   https://raw.githubusercontent.com/basitalisandhu/ai-agent-incidents/main/site/incidents.json
                          (the same file is served at https://basitalisandhu.github.io/ai-agent-incidents/incidents.json)
  4. the bundled snapshot ../../../data/incidents.json (always available)

--offline skips 2 and 3. --refresh ignores the cache. A network failure falls back to the bundle with a note on
stderr, so the command never fails because of the network. This is the only network call in the plugin.

Commands:
  list         filter (--vector, --outcome, --vendor, --product, --framework, --channel-in, --authority, --channel-out,
               --lens, --type, --since, --until, --cve, --adversarial, --owasp-agentic, --owasp-llm, --atlas, --tag,
               --status, --query, --limit)
  show ID      one record in full
  stats        counts per field (--by vector|outcome|channel_in|authority|channel_out|lens|type|year|vendor|product|
               framework|owasp_agentic|owasp_llm|mitre_atlas|tag|status), with the same filters
  fields       vocabulary of every coded field plus vendors, frameworks and mapping ids
  precedents   rank incidents against a design (--channel-in, --authority, --vector, --channel-out, or --design FILE)

Standard library only.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUNDLED = HERE.parents[2] / "data" / "incidents.json"
DEFAULT_URL = "https://raw.githubusercontent.com/basitalisandhu/ai-agent-incidents/main/site/incidents.json"
CACHE_TTL_S = 24 * 3600
FIELDS = ["type", "lens", "vector", "channel_in", "authority", "channel_out", "outcome"]
LIST_FIELDS = {"vendor": ("affected", "vendors"), "product": ("affected", "products"), "framework": ("affected", "frameworks"),
               "owasp_agentic": ("mappings", "owasp_agentic"), "owasp_llm": ("mappings", "owasp_llm"), "mitre_atlas": ("mappings", "mitre_atlas"),
               "tag": ("tags", None)}
COLUMNS = ["id", "date", "name", "vector", "channel_in", "authority", "outcome", "owasp_agentic", "url"]

# Controls that address each attack vector, phrased for a design review.
CONTROLS = {
    "indirect-injection": [
        "Provenance rule: designators (recipients, URLs, account ids) in a consequential call must come from the user's request or typed tool fields, never from third-party free text (a policy enforcement point in the tool executor).",
        "Approval gate on consequential tools with short-lived, single-use tokens (a credential broker with approval and single-use settings).",
        "Treat every tool result as untrusted: mark it, never let it widen the agent's permissions.",
    ],
    "direct-injection": [
        "Keep the system prompt free of user input; validate and bound user-controlled fields.",
        "Deterministic policy outside the model for anything consequential; the model is not the enforcement point.",
    ],
    "nhi-secrets": [
        "Give agents brokered, scoped, short-TTL credentials instead of raw keys (a credential broker that proxies calls or leases tokens).",
        "Secret scanning on agent config and instruction files (agent-config-audit); block secret printing in the shell (block-secret-exposure hook).",
    ],
    "supply-chain": [
        "Pin MCP servers, skills and packages to versions or digests; no `npx -y latest` in agent config.",
        "Review tool descriptions and skill files like code; run agent-config-audit in CI.",
    ],
    "excessive-agency": [
        "Least-privilege scopes per agent (`connector:METHOD:/path`), separate read and write connectors.",
        "Kill switch and per-agent key rotation.",
    ],
    "autonomous-ops": [
        "Human approval for destructive or irreversible actions; sandbox the workspace; no production credentials in dev agents.",
        "Tamper-evident audit log of every tool call with purpose (for example a hash chain).",
    ],
    "exploitation": ["Treat agent frameworks and MCP servers as internet-facing software: patch cadence, auth on every endpoint, no 0.0.0.0 binds without auth."],
    "exposure/misconfig": ["Authenticate every agent-facing service; audit permissions files for broad allow rules (agent-config-audit)."],
    "generated-code": ["Execute model-generated code only in a sandbox with no credentials and an egress allowlist."],
    "retrieval-memory": ["Provenance labels on memory and retrieved documents; memory writes need the same gating as external actions."],
    "poisoning": ["Verify model and dataset artefacts (signatures, safetensors over pickle); pin sources."],
    "extraction": ["Assume the system prompt is public; keep secrets and policy out of it."],
    "social-engineering": ["Out-of-band confirmation for payments and credential changes; agents cannot approve their own requests."],
    "availability": ["Rate limits per agent and per connector; budgets for tokens and tool calls."],
    "jailbreak": ["Do not rely on refusal training for security; enforce policy deterministically outside the model."],
}


# --------------------------------------------------------------------------- loading


def _cache_path(cache_dir: str | None) -> Path:
    base = Path(cache_dir) if cache_dir else Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "agent-security-skills" / "incidents.json"


def _normalise(entry: dict) -> dict:
    """Bring a record to the schema shape. Accepts the flat legacy shape (url, notes, vendors, cve string) too."""
    e = dict(entry)
    e["id"] = str(e.get("id", "")).strip()
    adv = e.get("adversarial")
    e["adversarial"] = adv.strip().lower() in {"yes", "true", "1"} if isinstance(adv, str) else bool(adv)
    cve = e.get("cve")
    if isinstance(cve, str):
        e["cve"] = [] if cve.strip() in {"", "-"} else [c.strip() for c in cve.split(",")]
    elif not isinstance(cve, list):
        e["cve"] = []
    for f in FIELDS + ["name", "date"]:
        e[f] = "" if e.get(f) is None else str(e.get(f, ""))
    sources = e.get("sources")
    if not isinstance(sources, list) or not sources:
        sources = [{"url": e["url"]}] if e.get("url") else []
    e["sources"] = [s if isinstance(s, dict) else {"url": str(s)} for s in sources]
    e["summary"] = str(e.get("summary") or e.get("notes") or "")
    m = e.get("mappings") if isinstance(e.get("mappings"), dict) else {}
    e["mappings"] = {k: [str(x) for x in (m.get(k) or [])] for k in ("owasp_agentic", "owasp_llm", "mitre_atlas")}
    a = e.get("affected") if isinstance(e.get("affected"), dict) else {}
    e["affected"] = {"vendors": [str(x) for x in (a.get("vendors") or e.get("vendors") or ([e["vendor"]] if e.get("vendor") else []))],
                     "products": [str(x) for x in (a.get("products") or [])], "frameworks": [str(x) for x in (a.get("frameworks") or [])]}
    e["tags"] = [str(x) for x in (e.get("tags") or [])]
    e["status"] = str(e.get("status") or "confirmed")
    e.pop("url", None); e.pop("notes", None); e.pop("vendors", None); e.pop("vendor", None)
    return e


def primary_url(e: dict) -> str:
    return e["sources"][0].get("url", "") if e["sources"] else ""


def _parse_dataset(raw) -> list[dict]:
    if isinstance(raw, list):
        entries = raw
    elif isinstance(raw, dict):
        for key in ("incidents", "data", "items", "entries"):
            if isinstance(raw.get(key), list):
                entries = raw[key]
                break
        else:
            raise ValueError("JSON object has no incidents list")
    else:
        raise ValueError("unexpected JSON shape")
    out = [_normalise(e) for e in entries if isinstance(e, dict)]
    if not out:
        raise ValueError("dataset is empty")
    return out


def load_incidents(args) -> tuple[list[dict], str]:
    """Return (incidents, source description)."""
    if args.data:
        return _parse_dataset(json.loads(Path(args.data).read_text(encoding="utf-8"))), f"file {args.data}"
    bundled = lambda why: (_parse_dataset(json.loads(BUNDLED.read_text(encoding="utf-8"))), f"bundled snapshot ({why})")  # noqa: E731
    if args.offline:
        return bundled("offline")
    cache = _cache_path(args.cache_dir)
    if cache.exists() and not args.refresh and time.time() - cache.stat().st_mtime < CACHE_TTL_S:
        try:
            return _parse_dataset(json.loads(cache.read_text(encoding="utf-8"))), f"cache {cache}"
        except Exception:  # noqa: BLE001
            pass
    url = os.environ.get("AGENT_SECURITY_INCIDENTS_URL", DEFAULT_URL)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "agent-security-skills/incident-lookup", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=float(os.environ.get("AGENT_SECURITY_FETCH_TIMEOUT", "10"))) as resp:
            if resp.status != 200:
                raise urllib.error.HTTPError(url, resp.status, "bad status", resp.headers, None)
            text = resp.read(20 * 1024 * 1024).decode("utf-8")
        incidents = _parse_dataset(json.loads(text))
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(text, encoding="utf-8")
        except OSError:
            pass
        return incidents, f"fetched {url}"
    except Exception as exc:  # noqa: BLE001
        if cache.exists():
            try:
                return _parse_dataset(json.loads(cache.read_text(encoding="utf-8"))), f"stale cache ({exc.__class__.__name__})"
            except Exception:  # noqa: BLE001
                pass
        print(f"incidents: using bundled snapshot; could not fetch {url} ({exc.__class__.__name__}: {exc})", file=sys.stderr)
        return bundled(f"fetch failed: {exc.__class__.__name__}")


# --------------------------------------------------------------------------- filtering


def _list_values(e: dict, key: str) -> list[str]:
    section, sub = LIST_FIELDS[key]
    return e[section] if sub is None else e[section][sub]


def _match_text(entry: dict, needle: str) -> bool:
    hay = " ".join([entry["name"], entry["summary"], " ".join(s.get("url", "") for s in entry["sources"]),
                    " ".join(entry["affected"]["vendors"] + entry["affected"]["products"] + entry["affected"]["frameworks"]),
                    " ".join(entry["tags"]), " ".join(entry["cve"])]).lower()
    return needle.lower() in hay


def filter_incidents(incidents: list[dict], args) -> list[dict]:
    out = []
    for e in incidents:
        ok = True
        for field in FIELDS:
            want = getattr(args, field, None)
            if want and e[field].lower() != want.lower():
                ok = False
                break
        if not ok:
            continue
        for key in ("vendor", "product", "framework"):
            want = getattr(args, key, None)
            if want:
                w = want.lower()
                if not any(w in x.lower() for x in _list_values(e, key)) and not (key == "vendor" and w in e["name"].lower()):
                    ok = False
                    break
        if not ok:
            continue
        for key in ("owasp_agentic", "owasp_llm", "mitre_atlas", "tag"):
            want = getattr(args, key, None)
            if want and not any(x.lower() == want.lower() or (key == "tag" and want.lower() in x.lower()) for x in _list_values(e, key)):
                ok = False
                break
        if not ok:
            continue
        if getattr(args, "status", None) and e["status"] != args.status:
            continue
        if getattr(args, "since", None) and e["date"][:7] < args.since:
            continue
        if getattr(args, "until", None) and e["date"][:7] > args.until:
            continue
        if getattr(args, "cve", False) and not e["cve"]:
            continue
        adv = getattr(args, "adversarial", None)
        if adv in {"yes", "no"} and e["adversarial"] != (adv == "yes"):
            continue
        if getattr(args, "query", None) and not _match_text(e, args.query):
            continue
        out.append(e)
    out.sort(key=lambda x: (x["date"], x["id"]), reverse=True)
    return out


# --------------------------------------------------------------------------- output


def _truncate(s: str, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "~"


def _cell_value(r: dict, c: str):
    if c == "url":
        return primary_url(r)
    if c == "cve":
        return ", ".join(r["cve"])
    if c in LIST_FIELDS:
        return ", ".join(_list_values(r, c))
    v = r.get(c)
    return ", ".join(v) if isinstance(v, list) else v


def render_table(rows: list[dict], columns: list[str], widths: dict[str, int] | None = None) -> str:
    widths = widths or {}
    cells = [[_truncate(_cell_value(r, c) if _cell_value(r, c) not in (None, "", []) else "-", widths.get(c, 40)) for c in columns] for r in rows]
    w = [max(len(c), *(len(row[i]) for row in cells)) if cells else len(c) for i, c in enumerate(columns)]
    lines = [" | ".join(c.ljust(w[i]) for i, c in enumerate(columns)), "-+-".join("-" * x for x in w)]
    lines += [" | ".join(row[i].ljust(w[i]) for i in range(len(columns))) for row in cells]
    return "\n".join(lines)


def render_markdown(rows: list[dict], columns: list[str]) -> str:
    def cell(r, c):
        v = _cell_value(r, c)
        if c == "name" and primary_url(r):
            return f"[{v}]({primary_url(r)})"
        return "-" if v in (None, "", []) else str(v).replace("|", "\\|")
    lines = ["| " + " | ".join(columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
    lines += ["| " + " | ".join(cell(r, c) for c in columns) + " |" for r in rows]
    return "\n".join(lines)


def emit(rows: list[dict], fmt: str, columns: list[str] = COLUMNS) -> None:
    if fmt == "json":
        print(json.dumps(rows, indent=1, ensure_ascii=False))
    elif fmt == "markdown":
        print(render_markdown(rows, [c for c in columns if c != "url"]))
    else:
        print(render_table(rows, columns, {"name": 56, "url": 60}))


# --------------------------------------------------------------------------- commands


def cmd_list(incidents, args):
    rows = filter_incidents(incidents, args)
    if args.limit:
        rows = rows[: args.limit]
    emit(rows, args.format)
    print(f"\n{len(rows)} incident(s)", file=sys.stderr)


def cmd_show(incidents, args):
    wanted = args.id.zfill(3) if args.id.isdigit() else args.id
    for e in incidents:
        if e["id"] == wanted or e["id"] == args.id:
            if args.format == "json":
                print(json.dumps(e, indent=1, ensure_ascii=False))
                return 0
            for k in ["id", "date", "name", "type", "lens", "vector", "channel_in", "authority", "channel_out", "adversarial", "outcome", "status"]:
                print(f"{k:14} {e.get(k) if e.get(k) not in (None, '') else '-'}")
            print(f"{'cve':14} {', '.join(e['cve']) or '-'}")
            print(f"{'owasp_agentic':14} {', '.join(e['mappings']['owasp_agentic']) or '-'}")
            print(f"{'owasp_llm':14} {', '.join(e['mappings']['owasp_llm']) or '-'}")
            print(f"{'mitre_atlas':14} {', '.join(e['mappings']['mitre_atlas']) or '-'}")
            for k in ("vendors", "products", "frameworks"):
                print(f"{k:14} {', '.join(e['affected'][k]) or '-'}")
            print(f"{'tags':14} {', '.join(e['tags']) or '-'}")
            print(f"{'summary':14} {e['summary']}")
            for i, s in enumerate(e["sources"]):
                label = "source" if i == 0 else f"source {i + 1}"
                extra = " ".join(f"({s[k]})" for k in ("title", "publisher") if s.get(k))
                print(f"{label:14} {s.get('url', '')} {extra}".rstrip())
            return 0
    print(f"no incident with id {args.id!r}", file=sys.stderr)
    return 1


def _stats(incidents, by: str) -> list[dict]:
    counter: collections.Counter = collections.Counter()
    for e in incidents:
        if by == "year":
            counter[e["date"][:4]] += 1
        elif by in LIST_FIELDS:
            for v in _list_values(e, by) or ["(none)"]:
                counter[v] += 1
        else:
            counter[e.get(by, "") or "-"] += 1
    total = len(incidents)
    return [{"value": k, "count": n, "share": f"{100 * n / total:.0f}%"} for k, n in counter.most_common()]


def cmd_stats(incidents, args):
    rows = filter_incidents(incidents, args)
    out = _stats(rows, args.by)
    if args.format == "json":
        print(json.dumps({"by": args.by, "total": len(rows), "rows": out}, indent=1))
    else:
        print(f"{args.by} over {len(rows)} incident(s)\n")
        emit(out, "markdown" if args.format == "markdown" else "table", ["value", "count", "share"])


def cmd_fields(incidents, args):
    data = {f: sorted({e[f] for e in incidents if e[f]}) for f in FIELDS}
    for key in LIST_FIELDS:
        data[key] = sorted({v for e in incidents for v in _list_values(e, key)})
    data["status"] = sorted({e["status"] for e in incidents})
    if args.format == "json":
        print(json.dumps(data, indent=1))
    else:
        for f, values in data.items():
            print(f"{f}:\n  " + "\n  ".join(values) + "\n")


def _load_design(path: str) -> dict:
    """A design file is JSON: {"name": "...", "channel_in": [...], "authority": [...], "vector": [...], "channel_out": [...]}.
    A flat 'key: a, b' text file is accepted too, so users need no YAML parser."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = {}
        for line in text.splitlines():
            if ":" in line and not line.strip().startswith("#"):
                k, v = line.split(":", 1)
                k = k.strip().replace("-", "_")
                vals = [x.strip().strip("[]\"'") for x in v.replace("[", "").replace("]", "").split(",") if x.strip()]
                data[k] = vals if k in {"channel_in", "authority", "vector", "channel_out"} else v.strip()
    return data


def rank_precedents(incidents: list[dict], channels_in: list[str], authorities: list[str], vectors: list[str], channel_out: list[str] | None = None) -> list[dict]:
    ci, au, ve, co = ({x.lower() for x in xs} for xs in (channels_in, authorities, vectors, channel_out or []))
    ranked = []
    for e in incidents:
        score, why = 0, []
        if e["channel_in"].lower() in ci:
            score += 3; why.append(f"input via {e['channel_in']}")
        if e["authority"].lower() in au:
            score += 3; why.append(f"authority {e['authority']}")
        if e["vector"].lower() in ve:
            score += 2; why.append(f"vector {e['vector']}")
        if e["channel_out"].lower() in co:
            score += 1; why.append(f"impact via {e['channel_out']}")
        if score:
            row = dict(e); row["score"] = score; row["why"] = "; ".join(why); row["url"] = primary_url(e)
            ranked.append(row)
    ranked.sort(key=lambda r: (-r["score"], r["date"]), reverse=False)
    ranked.sort(key=lambda r: r["score"], reverse=True)
    return ranked


def cmd_precedents(incidents, args):
    channels_in, authorities, vectors, channel_out = list(args.channel_in or []), list(args.authority or []), list(args.vector or []), list(args.channel_out or [])
    name = "the design"
    if args.design:
        d = _load_design(args.design)
        channels_in += d.get("channel_in", []) or []; authorities += d.get("authority", []) or []
        vectors += d.get("vector", []) or []; channel_out += d.get("channel_out", []) or []
        name = d.get("name", name)
    if not (channels_in or authorities or vectors or channel_out):
        print("precedents: give at least one of --channel-in, --authority, --vector, --channel-out or --design", file=sys.stderr)
        return 2
    ranked = rank_precedents(incidents, channels_in, authorities, vectors, channel_out)
    top = ranked[: args.limit] if args.limit else ranked
    frameworks = {"owasp_agentic": _stats(ranked, "owasp_agentic"), "owasp_llm": _stats(ranked, "owasp_llm"), "mitre_atlas": _stats(ranked, "mitre_atlas")}
    if args.format == "json":
        print(json.dumps({"design": name, "inputs": {"channel_in": channels_in, "authority": authorities, "vector": vectors, "channel_out": channel_out},
                          "matched": len(ranked), "shown": len(top), "precedents": top, "outcomes": _stats(ranked, "outcome"),
                          "vectors": _stats(ranked, "vector"), "frameworks": frameworks,
                          "controls": {v: CONTROLS.get(v, []) for v in sorted({r["vector"] for r in ranked})}}, indent=1, ensure_ascii=False))
        return 0
    md = args.format == "markdown"
    print(f"Precedents for {name}: {len(ranked)} matching incident(s), showing {len(top)}\n")
    cols = ["id", "date", "name", "score", "why", "outcome", "owasp_agentic"]
    print(render_markdown(top, cols) if md else render_table(top, cols, {"name": 52, "why": 48}))
    if ranked:
        print("\nOutcomes among matches:")
        for s in _stats(ranked, "outcome"):
            print(f"  {s['value']:24} {s['count']:3}  {s['share']}")
        print("\nOWASP Agentic Top 10 among matches:")
        for s in frameworks["owasp_agentic"][:6]:
            print(f"  {s['value']:24} {s['count']:3}  {s['share']}")
        print("\nControls that would have helped:")
        for v in sorted({r["vector"] for r in ranked}):
            print(f"  [{v}]")
            for line in CONTROLS.get(v, []):
                print(f"    - {line}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="incidents.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", help="explicit dataset JSON file")
    ap.add_argument("--offline", action="store_true", help="never touch the network; use the bundled snapshot")
    ap.add_argument("--refresh", action="store_true", help="ignore the cache and fetch again")
    ap.add_argument("--cache-dir", help="cache directory (default: $XDG_CACHE_HOME or ~/.cache)")
    ap.add_argument("--format", choices=["table", "json", "markdown"], default="table")
    sub = ap.add_subparsers(dest="command", required=True)

    def add_filters(p):
        p.add_argument("--vector"); p.add_argument("--outcome"); p.add_argument("--lens"); p.add_argument("--type")
        p.add_argument("--channel-in", dest="channel_in"); p.add_argument("--authority"); p.add_argument("--channel-out", dest="channel_out")
        p.add_argument("--vendor", help="substring of affected.vendors or the name"); p.add_argument("--product"); p.add_argument("--framework")
        p.add_argument("--owasp-agentic", dest="owasp_agentic", help="e.g. ASI01"); p.add_argument("--owasp-llm", dest="owasp_llm", help="e.g. LLM01")
        p.add_argument("--atlas", dest="mitre_atlas", help="e.g. AML.T0051"); p.add_argument("--tag"); p.add_argument("--status", choices=["confirmed", "reported", "disputed"])
        p.add_argument("--since", help="YYYY-MM"); p.add_argument("--until", help="YYYY-MM")
        p.add_argument("--cve", action="store_true", help="only incidents with a CVE")
        p.add_argument("--adversarial", choices=["yes", "no"]); p.add_argument("--query", help="substring over name, summary, sources, affected, tags, cve")

    p = sub.add_parser("list", help="filter incidents"); add_filters(p); p.add_argument("--limit", type=int, default=0); p.set_defaults(fn=cmd_list)
    p = sub.add_parser("show", help="one incident in full"); p.add_argument("id"); p.set_defaults(fn=cmd_show)
    p = sub.add_parser("stats", help="counts per field"); add_filters(p)
    p.add_argument("--by", default="vector", choices=FIELDS + ["year", "status"] + list(LIST_FIELDS)); p.set_defaults(fn=cmd_stats)
    p = sub.add_parser("fields", help="field vocabularies"); p.set_defaults(fn=cmd_fields)
    p = sub.add_parser("precedents", help="rank incidents against a design")
    p.add_argument("--channel-in", dest="channel_in", action="append"); p.add_argument("--authority", action="append")
    p.add_argument("--vector", action="append"); p.add_argument("--channel-out", dest="channel_out", action="append")
    p.add_argument("--design", help="JSON file with channel_in/authority/vector lists")
    p.add_argument("--limit", type=int, default=15); p.set_defaults(fn=cmd_precedents)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    incidents, source = load_incidents(args)
    print(f"incidents: {len(incidents)} entries from {source}", file=sys.stderr)
    rc = args.fn(incidents, args)
    return int(rc or 0)


if __name__ == "__main__":
    sys.exit(main())
