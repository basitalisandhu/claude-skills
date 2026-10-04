#!/usr/bin/env python3
"""Flag sentences in an onboarding guide that make claims no fact supports.

Input: the guide (Markdown) and the JSON written by onboarding_facts.py. Each sentence, list item, table row
and code-block line is read for checkable tokens:
  code       anything in backticks (paths, commands, names, versions)
  path       path-like words outside backticks (inventory/cli.py, web/)
  env        UPPER_CASE_NAMES with an underscore
  owner      @handles and @org/team names
  service    named external services (PostgreSQL, Redis, AWS, Stripe and the other names the facts script knows)
  citation   path:line references and [F12] fact ids written into the guide
and each token must match a fact's terms. Rules:
  ONB-UNSUPPORTED  a sentence with at least one token that no fact supports
  ONB-CITE         a path:line citation or fact id that is not in the facts file
  ONB-NOFACT       a sentence that asserts ownership, a dependency, a connection or a location in words but
                   names nothing checkable ("the service talks to the payment gateway")
Sentences with no tokens and no such verbs are counted as unchecked prose, not flagged. Exit codes: 0 every
claim is supported, 1 findings, 2 bad input. Reads the two files only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SERVICE_ALIASES = {
    "postgresql": "PostgreSQL", "postgres": "PostgreSQL", "mysql": "MySQL", "mariadb": "MySQL", "redis": "Redis",
    "mongodb": "MongoDB", "mongo": "MongoDB", "rabbitmq": "RabbitMQ", "kafka": "Kafka",
    "elasticsearch": "Elasticsearch", "aws": "AWS", "s3": "AWS", "dynamodb": "AWS", "sqs": "AWS",
    "gcp": "Google Cloud", "bigquery": "Google Cloud", "azure": "Azure", "stripe": "Stripe", "sentry": "Sentry",
    "smtp": "SMTP mail", "sendgrid": "SMTP mail", "mailgun": "SMTP mail", "slack": "Slack", "sqlite": "SQLite",
}
SERVICE_RE = re.compile(r"\b(" + "|".join(sorted(SERVICE_ALIASES, key=len, reverse=True)) + r")\b", re.IGNORECASE)
CLAIM_VERBS = re.compile(
    r"\b(owned by|owns|maintained by|connects? to|talks? to|calls (?:out )?to|depends on|deploys? to|deployed to|"
    r"is stored in|are stored in|lives? in|reads? from|writes? to|sends? .{0,20}to|entry ?point is)\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://\S+")
LINK_RE = re.compile(r"\]\(([^)]*)\)")
CODE_RE = re.compile(r"`([^`]+)`")
CITE_RE = re.compile(r"(?<![\w/.-])((?:[\w.-]+/)*[\w.-]+\.[A-Za-z0-9]+|(?:[\w.-]+/)+):(\d+)\b")
FACT_ID_RE = re.compile(r"\[(F\d+)\]")
ENV_RE = re.compile(r"\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b")
OWNER_RE = re.compile(r"(?<![\w.])@[A-Za-z0-9][\w-]*(?:/[\w-]+)?")
PATH_RE = re.compile(r"(?<![\w@/.-])(?:\.?[\w-]+/)+[\w.-]*(?![\w/])")
FILE_RE = re.compile(r"(?<![\w@/.-])[\w-]+\.(?:py|js|ts|tsx|jsx|mjs|cjs|toml|json|ya?ml|cfg|ini|sh|md|txt|lock)\b")
SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z`(\[@])")
COMMAND_HEADS = {"python", "python3", "pip", "pip3", "npm", "npx", "yarn", "pnpm", "bun", "make", "just", "pytest",
                 "docker", "cd", "uv", "poetry", "go", "cargo", "node", "tox", "nox"}


def norm(token: str) -> str:
    t = token.strip().strip("`").strip()
    t = re.sub(r"^\$\s+", "", t)
    t = t.rstrip(".,;:")
    if t.startswith("./"):
        t = t[2:]
    return re.sub(r"\s+", " ", t)


def canon_cmd(t: str) -> str:
    t = re.sub(r"\bpython3\b", "python", t)
    t = re.sub(r"\bpip3\b", "pip", t)
    return t


class Index:
    def __init__(self, facts: list[dict]) -> None:
        self.facts = facts
        self.terms: dict[str, set[str]] = {}
        self.services: dict[str, set[str]] = {}
        self.citations = {f.get("citation", "") for f in facts}
        self.ids = {f.get("id", "") for f in facts}
        for f in facts:
            for t in f.get("terms", []):
                key = canon_cmd(norm(str(t)))
                if key:
                    self.terms.setdefault(key, set()).add(f["id"])
                    self.terms.setdefault(key.rstrip("/"), set()).add(f["id"])
            if f.get("kind") == "external_service" and f.get("service"):
                self.services.setdefault(f["service"], set()).add(f["id"])

    def support(self, kind: str, token: str) -> set[str]:
        if kind == "service":
            return self.services.get(SERVICE_ALIASES[token.lower()], set())
        t = canon_cmd(norm(token))
        if not t:
            return {"-"}
        if t in self.terms:
            return self.terms[t]
        bare = t.rstrip("/")
        if bare in self.terms:
            return self.terms[bare]
        hits: set[str] = set()
        if kind in {"path", "code"} and ("/" in t or "." in t) and " " not in t:
            for term, ids in self.terms.items():
                if term.startswith(bare + "/"):
                    hits |= ids
        if not hits and kind == "code":
            if " " in t:
                for term, ids in self.terms.items():
                    if " " in term and t in term:
                        hits |= ids
            elif re.fullmatch(r"[A-Za-z][\w-]*", t):
                word = re.compile(rf"(?<![\w-]){re.escape(t)}(?![\w-])")
                for term, ids in self.terms.items():
                    if " " in term and word.search(term):
                        hits |= ids
        return hits


def tokens_of(sentence: str) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """Return (kind, token) pairs, path:line citations and fact ids found in one sentence."""
    s = LINK_RE.sub("]", URL_RE.sub(" ", sentence))
    cites = [f"{m.group(1)}:{m.group(2)}" for m in CITE_RE.finditer(s)]
    ids = FACT_ID_RE.findall(s)
    s = FACT_ID_RE.sub(" ", s)
    toks: list[tuple[str, str]] = []
    for m in CODE_RE.finditer(s):
        inner = m.group(1).strip()
        if CITE_RE.fullmatch(inner):
            continue
        toks.append(("code", inner))
    rest = CODE_RE.sub(" ", s)
    rest = CITE_RE.sub(" ", rest)
    toks += [("owner", m.group(0)) for m in OWNER_RE.finditer(rest)]
    rest = OWNER_RE.sub(" ", rest)
    toks += [("env", m.group(0)) for m in ENV_RE.finditer(rest)]
    toks += [("path", m.group(0)) for m in PATH_RE.finditer(rest) if len(m.group(0).strip("/")) > 1]
    rest = PATH_RE.sub(" ", rest)
    toks += [("path", m.group(0)) for m in FILE_RE.finditer(rest)]
    toks += [("service", m.group(1)) for m in SERVICE_RE.finditer(rest)]
    seen: set[tuple[str, str]] = set()
    out = []
    for t in toks:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out, cites, ids


def units(text: str) -> list[tuple[int, str, bool]]:
    """Split the guide into (line, text, is_code_line) units: sentences outside fences, lines inside them."""
    out: list[tuple[int, str, bool]] = []
    in_fence = False
    para: list[tuple[int, str]] = []

    def flush() -> None:
        if not para:
            return
        start = para[0][0]
        joined = " ".join(t for _, t in para)
        for sent in SENT_SPLIT.split(joined):
            if sent.strip():
                out.append((start, sent.strip(), False))
        para.clear()

    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if re.match(r"^\s*(```|~~~)", line):
            flush()
            in_fence = not in_fence
            continue
        if in_fence:
            s = line.strip()
            if s and not s.startswith("#"):
                out.append((i, s, True))
            continue
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("<!--") or re.fullmatch(r"\|?[\s:|-]+\|?", s):
            flush()
            continue
        if s.startswith("|"):
            flush()
            out.append((i, s.strip("|").replace("|", ";"), False))
            continue
        if re.match(r"^([-*+]|\d+[.)])\s+", s):
            flush()
            s = re.sub(r"^([-*+]|\d+[.)])\s+", "", s)
        para.append((i, s))
    flush()
    return out


def lint(guide_text: str, facts: list[dict], allow: set[str]) -> dict:
    idx = Index(facts)
    findings: list[dict] = []
    stats = {"units": 0, "claims": 0, "supported": 0, "unchecked": 0}
    used: set[str] = set()
    for line, text, is_code in units(guide_text):
        stats["units"] += 1
        if is_code:
            toks: list[tuple[str, str]] = [("code", text)]
            cites, ids = [], []
        else:
            toks, cites, ids = tokens_of(text)
        toks = [(k, t) for k, t in toks if norm(t) not in allow and t not in allow]
        bad_cites = [c for c in cites if c not in idx.citations] + [i for i in ids if i not in idx.ids]
        if not toks and not cites and not ids:
            if CLAIM_VERBS.search(text):
                stats["claims"] += 1
                findings.append({"rule": "ONB-NOFACT", "line": line, "text": text, "unmatched": [],
                                 "detail": "asserts a relationship but names nothing a fact can support"})
            else:
                stats["unchecked"] += 1
            continue
        stats["claims"] += 1
        unmatched = []
        for kind, tok in toks:
            hits = idx.support(kind, tok)
            if hits:
                used |= hits
            else:
                unmatched.append(tok)
        used |= {c for c in ids if c in idx.ids}
        if unmatched:
            findings.append({"rule": "ONB-UNSUPPORTED", "line": line, "text": text, "unmatched": unmatched,
                             "detail": "no fact supports: " + ", ".join(unmatched)})
        if bad_cites:
            findings.append({"rule": "ONB-CITE", "line": line, "text": text, "unmatched": bad_cites,
                             "detail": "citation not in the facts file: " + ", ".join(bad_cites)})
        if not unmatched and not bad_cites:
            stats["supported"] += 1
    kinds = sorted({f["kind"] for f in facts})
    used_kinds = sorted({f["kind"] for f in facts if f["id"] in used})
    return {"stats": stats, "findings": findings, "facts_used": sorted(used, key=lambda x: int(x[1:]) if
                                                                         x[1:].isdigit() else 0),
            "fact_kinds_not_mentioned": [k for k in kinds if k not in used_kinds]}


def render(path: str, rep: dict) -> str:
    st = rep["stats"]
    out = [f"Onboarding guide lint: {path}",
           f"{st['claims']} claims: {st['supported']} supported, {len(rep['findings'])} finding(s); "
           f"{st['unchecked']} sentences of unchecked prose", ""]
    for f in rep["findings"]:
        out.append(f"{f['rule']:<16} line {f['line']:<4} {f['detail']}")
        out.append(f"{'':<16} {f['text'][:150]}")
    if rep["fact_kinds_not_mentioned"]:
        out.append("")
        out.append("Fact kinds the guide never uses: " + ", ".join(rep["fact_kinds_not_mentioned"]))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="onboarding_lint.py",
                                 description="Flag onboarding-guide sentences whose claims no fact supports.")
    ap.add_argument("guide", help="the onboarding guide (Markdown)")
    ap.add_argument("facts", help="JSON written by onboarding_facts.py --json or --out")
    ap.add_argument("--allow", action="append", default=[], metavar="TOKEN",
                    help="a token to accept without a fact, for example a tool name (repeatable)")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args(argv)
    try:
        guide = Path(args.guide).read_text(encoding="utf-8")
        data = json.loads(Path(args.facts).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    facts = data.get("facts") if isinstance(data, dict) else None
    if not isinstance(facts, list) or not all(isinstance(f, dict) and "id" in f for f in facts):
        print("error: the facts file has no 'facts' list from onboarding_facts.py", file=sys.stderr)
        return 2
    rep = lint(guide, facts, set(args.allow))
    rep = {"guide": args.guide, **rep}
    print(json.dumps(rep, indent=2) if args.json else render(args.guide, rep))
    return 1 if rep["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
