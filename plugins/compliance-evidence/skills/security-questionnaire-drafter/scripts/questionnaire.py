#!/usr/bin/env python3
"""Draft answers to a vendor security questionnaire from an evidence pack and a policy folder on disk, citing the
file behind every answer and marking questions with no evidence as not assessable instead of inventing an answer.

Inputs:
  questionnaire   CSV (the column whose header contains "question" holds the questions; an "id", "#", "no", "ref"
                  or "number" column is used as the question id) or Markdown (a table with a "Question" column,
                  numbered or bulleted list items, or lines ending in "?"). Export XLSX questionnaires to CSV first.
  --evidence      an evidence pack folder with manifest.json (from evidence-pack-builder), or any folder of files.
                  In a pack, each file's SHA-256 is checked; a file that fails the check is never cited.
  --policies      a folder of policy documents (.md, .markdown, .txt). Markdown files are split into sections at
                  headings; a .txt file is one section.
  --control-map   optional control-map JSON (from control-map-from-exports). A question that names a control
                  identifier in the map (for example A.8.15 or CC6.1) takes that control's state and citations.

Matching: each question is reduced to keywords (stop words removed, common synonyms grouped, for example MFA,
multi-factor and two-factor). A policy section scores 3 per keyword in its heading and 1 per keyword in its text; an
evidence file scores 3 per synonym group and 2 per other keyword found in its path, command, description or
source system. Matches at or above
--min-score (default 3) are cited, at most --max-cites per kind (default 3), best first, ties broken by name.

Result states (one per question):
  supported       at least one policy section or evidence file matched; the draft quotes and cites them
  contradicted    the question names a control the control map marks contradicted
  not assessable  nothing matched (or the named control is not assessable); the draft says so and asks for an owner

Every draft is preparation for a human assessor and for the person who signs the questionnaire: it is not an
answer until someone with authority confirms it. The script never writes "Yes" or "No" for you.

Output: Markdown (default) or --json, to stdout or --out; --csv writes id, question, state, basis, draft_answer,
citations and an empty owner column. Secret-shaped strings are masked; --redact also replaces e-mail addresses with
stable tokens.

Exit codes: 0 every question supported, 1 a question is not assessable or contradicted (a person must answer it; see
--fail-on), 2 bad input. Standard library only. Reads files only; no network.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sys
from pathlib import Path

SUPPORTED, CONTRADICTED, NOT_ASSESSABLE = "supported", "contradicted", "not assessable"
DISCLAIMER = "Preparation for a human assessor and the questionnaire owner: drafts only, not an attestation or an audit opinion."
STOP = set(
    """a an and any are as at be been by can do does each for from has have how if in into is it its of on or our
    please provide describe explain list your you we us that the this these those to with within which what when where who
    whether will would should shall must may there their they them than then also all such other per via yes no not n/a
    company organisation organization vendor service services system systems data information process processes
    procedure procedures documented document documents ensure ensured place used use using""".split()
)
SYNONYMS = [
    {"mfa", "multi-factor", "multifactor", "2fa", "two-factor", "authenticator"},
    {"encrypt", "encryption", "encrypted", "kms", "tls", "cryptographic", "cryptography", "at-rest", "in-transit"},
    {"backup", "backups", "restore", "restoration", "snapshot", "snapshots"},
    {"log", "logs", "logging", "audit", "cloudtrail", "monitoring", "siem"},
    {"vulnerability", "vulnerabilities", "patch", "patches", "patching", "dependabot", "scan", "scanning", "pentest", "penetration"},
    {"privilege", "privileged", "admin", "administrator", "administrative", "least", "rbac", "role", "roles"},
    {"incident", "incidents", "breach", "breaches"},
    {"training", "awareness", "phishing"},
    {"password", "passwords", "passphrase", "credential", "credentials"},
    {"change", "changes", "approval", "approvals", "pull", "merge", "branch"},
    {"supplier", "suppliers", "third-party", "subprocessor", "subprocessors", "vendors"},
    {"retention", "retain", "deletion", "disposal", "destroy"},
    {"continuity", "disaster", "dr", "bcp", "resilience"},
    {"asset", "assets", "inventory"},
    {"risk", "risks", "assessment"},
    {"access", "accounts", "account", "permission", "permissions", "offboarding", "onboarding", "joiner", "leaver"},
    {"firewall", "network", "segmentation", "vpc", "security-group"},
    {"malware", "antivirus", "endpoint", "edr", "defender", "guardduty"},
]
CONCEPT = {w: f"group{i}" for i, g in enumerate(SYNONYMS) for w in g}
WORD_RE = re.compile(r"[a-z0-9][a-z0-9-]*")
CONTROL_ID_RE = re.compile(r"\b(A\.\d+\.\d+|CC\d+\.\d+|A1\.\d+|C1\.\d+|PI1\.\d+|P\d+\.\d+)\b")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+'#-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
SECRET_RES = [
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9-]{10,})"),
]
POLICY_SUFFIXES = {".md", ".markdown", ".txt"}
MAX_BYTES = 5 * 1024 * 1024


class InputError(Exception):
    """Bad or unreadable input. Exit 2."""


def read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_BYTES:
            raise InputError(f"{path.name}: larger than 5 MB")
        return path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"{path.name}: not UTF-8 text") from exc


def concepts(text: str) -> set[str]:
    out = set()
    words = WORD_RE.findall(text.lower().replace("_", " ").replace("/", " "))
    parts = [part for word in words if "-" in word and word not in CONCEPT for part in word.split("-") if part]
    for w in words + parts:
        if w in STOP or len(w) < 3 and w not in CONCEPT:
            continue
        stem = w[:-1] if w.endswith("s") and len(w) > 4 and w[:-1] in CONCEPT else w
        out.add(CONCEPT.get(stem, stem))
    return out


# --- questionnaire ---------------------------------------------------------------------------------------------


def parse_csv(text: str) -> list[dict]:
    rows = list(csv.reader(io.StringIO(text)))
    if not rows or not any(c.strip() for c in rows[0]):
        raise InputError("questionnaire CSV has no header row")
    header = [h.strip().lower() for h in rows[0]]
    q_col = next((i for i, h in enumerate(header) if "question" in h and h not in ("question id", "question_id", "question no")), None)
    if q_col is None:
        raise InputError("questionnaire CSV needs a column whose header contains 'question'")
    id_col = next((i for i, h in enumerate(header) if h in ("id", "#", "no", "no.", "ref", "number", "question id", "question_id")), None)
    out = []
    for n, r in enumerate(rows[1:], 1):
        q = r[q_col].strip() if q_col < len(r) else ""
        if q:
            qid = r[id_col].strip() if id_col is not None and id_col < len(r) and r[id_col].strip() else str(n)
            out.append({"id": qid, "question": q})
    return out


def parse_markdown(text: str) -> list[dict]:
    lines = text.splitlines()
    out: list[dict] = []
    for i, line in enumerate(lines):
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if line.strip().startswith("|") else []
        if cells and any("question" in c.lower() for c in cells) and i + 1 < len(lines) and re.match(r"^\s*\|?\s*:?-{3,}", lines[i + 1]):
            q_col = next(j for j, c in enumerate(cells) if "question" in c.lower())
            id_col = next((j for j, c in enumerate(cells) if c.lower() in ("id", "#", "no", "ref", "number")), None)
            for row in lines[i + 2 :]:
                if not row.strip().startswith("|"):
                    break
                rc = [c.strip() for c in row.strip().strip("|").split("|")]
                if q_col < len(rc) and rc[q_col]:
                    qid = rc[id_col] if id_col is not None and id_col < len(rc) and rc[id_col] else str(len(out) + 1)
                    out.append({"id": qid, "question": rc[q_col]})
            return out
    for line in lines:
        m = re.match(r"^\s*(?:(\d+(?:\.\d+)*)[.)]|[-*])\s+(.+)$", line)
        if m:
            out.append({"id": m.group(1) or str(len(out) + 1), "question": m.group(2).strip()})
    if not out:
        out = [{"id": str(n), "question": ln.strip()} for n, ln in enumerate((ln for ln in lines if ln.strip().endswith("?")), 1)]
    return out


def load_questions(path: Path) -> list[dict]:
    text = read(path)
    qs = parse_csv(text) if path.suffix.lower() == ".csv" else parse_markdown(text)
    if not qs:
        raise InputError(f"{path.name}: no questions found")
    seen: dict[str, int] = {}
    for q in qs:
        seen[q["id"]] = seen.get(q["id"], 0) + 1
        if seen[q["id"]] > 1:
            q["id"] = f"{q['id']}-{seen[q['id']]}"
    return qs


# --- sources ---------------------------------------------------------------------------------------------------


def load_policies(folder: Path | None) -> list[dict]:
    if folder is None:
        return []
    if not folder.is_dir():
        raise InputError(f"{folder}: --policies must be a folder")
    sections = []
    for p in sorted(f for f in folder.rglob("*") if f.is_file() and f.suffix.lower() in POLICY_SUFFIXES):
        name = p.relative_to(folder).as_posix()
        text = read(p)
        if p.suffix.lower() == ".txt":
            sections.append({"file": name, "heading": p.stem, "text": text})
            continue
        heading, buf = p.stem, []
        for line in text.splitlines() + ["# end"]:
            m = HEADING_RE.match(line)
            if m:
                body = "\n".join(buf).strip()
                if body:
                    sections.append({"file": name, "heading": heading, "text": body})
                heading, buf = m.group(2).strip(), []
            else:
                buf.append(line)
    for s in sections:
        s["h_concepts"], s["b_concepts"] = concepts(s["heading"]), concepts(s["text"])
    return sections


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_evidence(folder: Path | None) -> tuple[list[dict], list[str]]:
    if folder is None:
        return [], []
    if not folder.is_dir():
        raise InputError(f"{folder}: --evidence must be a folder")
    manifest = folder / "manifest.json"
    files, notes = [], []
    if manifest.is_file():
        try:
            doc = json.loads(read(manifest))
        except json.JSONDecodeError as exc:
            raise InputError(f"manifest.json: invalid JSON: {exc}") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("files"), list):
            raise InputError("manifest.json: expected an evidence pack manifest with a files list")
        root = Path(doc["source_root"]) if doc.get("mode") == "reference" and doc.get("source_root") else folder / "evidence"
        for f in doc["files"]:
            if not isinstance(f, dict) or not f.get("path"):
                raise InputError("manifest.json: every file entry needs a path")
            p = root / f["path"]
            if not p.is_file():
                notes.append(f"{f['path']}: listed in the manifest but not found; not cited")
                continue
            if f.get("sha256") and sha256(p) != f["sha256"]:
                notes.append(f"{f['path']}: SHA-256 does not match the manifest; not cited")
                continue
            files.append(
                {
                    "path": f["path"],
                    "collected_at": f.get("collected_at", ""),
                    "sha256": f.get("sha256", ""),
                    "text": " ".join(str(f.get(k) or "") for k in ("path", "command", "description", "source_system")),
                }
            )
    else:
        notes.append("no manifest.json: files are cited by path without a hash check")
        for p in sorted(x for x in folder.rglob("*") if x.is_file()):
            rel = p.relative_to(folder).as_posix()
            files.append({"path": rel, "collected_at": "", "sha256": "", "text": rel})
    for f in files:
        f["concepts"] = concepts(f["text"])
    return files, notes


def load_control_map(path: Path | None) -> dict[str, dict]:
    if path is None:
        return {}
    try:
        doc = json.loads(read(path))
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: invalid JSON: {exc}") from exc
    controls = doc.get("controls") if isinstance(doc, dict) else None
    if not isinstance(controls, list):
        raise InputError(f"{path.name}: expected control-map JSON with a controls list")
    return {c["id"]: c for c in controls if isinstance(c, dict) and c.get("id")}


# --- drafting --------------------------------------------------------------------------------------------------


def excerpt(text: str, limit: int = 280) -> str:
    flat = " ".join(re.sub(r"^[#>*\-\d.)\s]+", "", ln) for ln in text.splitlines() if ln.strip())
    sents = re.split(r"(?<=[.!?])\s+", flat)
    out = ""
    for s in sents:
        if len(out) + len(s) > limit:
            break
        out = (out + " " + s).strip()
    return out or flat[: limit - 3] + "..."


def draft(q: dict, policies: list[dict], evidence: list[dict], cmap: dict[str, dict], args) -> dict:
    qc = concepts(q["question"])
    named = [cid for cid in CONTROL_ID_RE.findall(q["question"]) if cid in cmap]
    if named:
        ctl = cmap[named[0]]
        cites = [f"[evidence: {c.get('file')}#{c.get('field')}]" for c in ctl.get("citations") or [] if isinstance(c, dict)]
        state = ctl.get("state") if ctl.get("state") in (SUPPORTED, CONTRADICTED, NOT_ASSESSABLE) else NOT_ASSESSABLE
        text = {
            SUPPORTED: f"Draft for review: control {named[0]} is supported in the control map. " + " ".join(cites),
            CONTRADICTED: f"Draft for review: control {named[0]} is contradicted in the control map, so this cannot be answered as met. "
            + "; ".join(ctl.get("gaps") or [])
            + " "
            + " ".join(cites),
            NOT_ASSESSABLE: f"Not assessable: control {named[0]} is not assessable in the control map. " + "; ".join(ctl.get("gaps") or []),
        }[state]
        return {"id": q["id"], "question": q["question"], "state": state, "basis": "control map", "draft_answer": text.strip(), "citations": cites}
    scored_p = []
    for s in policies:
        score = 3 * len(qc & s["h_concepts"]) + min(len(qc & s["b_concepts"]), 4)
        if score >= args.min_score:
            scored_p.append((-score, s["file"], s["heading"], s))
    scored_e = []
    for f in evidence:
        shared = qc & f["concepts"]
        score = sum(3 if c.startswith("group") else 2 for c in shared)
        if score >= args.min_score:
            scored_e.append((-score, f["path"], f))
    scored_p.sort(key=lambda x: x[:3])
    scored_e.sort(key=lambda x: x[:2])
    pol = [x[3] for x in scored_p[: args.max_cites]]
    ev = [x[2] for x in scored_e[: args.max_cites]]
    if not pol and not ev:
        return {
            "id": q["id"],
            "question": q["question"],
            "state": NOT_ASSESSABLE,
            "basis": "none",
            "draft_answer": (
                "Not assessable from the evidence pack and policies provided: no policy section or evidence file matched. "
                "Route to an owner; do not answer from memory."
            ),
            "citations": [],
        }
    parts, cites = ["Draft for review."], []
    for s in pol:
        c = f"[policy: {s['file']}#{s['heading']}]"
        parts.append(f'{s["file"]}, section "{s["heading"]}", states: "{excerpt(s["text"])}" {c}')
        cites.append(c)
    if ev:
        listed = []
        for f in ev:
            c = f"[evidence: {f['path']}]"
            when = f", collected {f['collected_at'][:10]}" if f.get("collected_at") else ""
            listed.append(f"{f['path']}{when} {c}")
            cites.append(c)
        parts.append("Supporting evidence on file: " + "; ".join(listed) + ".")
    basis = "policy and evidence" if pol and ev else "policy" if pol else "evidence"
    return {"id": q["id"], "question": q["question"], "state": SUPPORTED, "basis": basis, "draft_answer": " ".join(parts), "citations": cites}


def scrub(text: str, redact: bool) -> str:
    for rx in SECRET_RES:
        text = rx.sub("[masked secret]", text)
    if redact:
        text = EMAIL_RE.sub(lambda m: "user-" + hashlib.sha256(m.group(0).lower().encode()).hexdigest()[:8] + "@redacted.invalid", text)
    return text


def cell(v) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("`", "'")


def render(rep: dict) -> str:
    c = rep["counts"]
    lines = [
        "## Security questionnaire draft",
        "",
        f"{rep['questions']} questions: {c[SUPPORTED]} `{SUPPORTED}`, {c[CONTRADICTED]} `{CONTRADICTED}`, {c[NOT_ASSESSABLE]} `{NOT_ASSESSABLE}`.",
        "",
        "| ID | Question | State | Basis | Draft answer |",
        "|---|---|---|---|---|",
    ]
    lines += [f"| {cell(a['id'])} | {cell(a['question'])} | {a['state']} | {a['basis']} | {cell(a['draft_answer'])} |" for a in rep["answers"]]
    if rep["notes"]:
        lines += ["", "### Notes on the inputs", ""] + [f"- {cell(n)}" for n in rep["notes"]]
    lines += ["", rep["disclaimer"]]
    return "\n".join(lines)


def answers_csv(answers: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["id", "question", "state", "basis", "draft_answer", "citations", "owner"])
    for a in answers:
        w.writerow([a["id"], a["question"], a["state"], a["basis"], a["draft_answer"], " ".join(a["citations"]), ""])
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("questionnaire", help="questionnaire as CSV or Markdown")
    ap.add_argument("--evidence", help="evidence pack folder (with manifest.json) or any folder of evidence files")
    ap.add_argument("--policies", help="folder of policy documents (.md, .txt)")
    ap.add_argument("--control-map", help="control-map JSON from control-map-from-exports")
    ap.add_argument("--min-score", type=int, default=3, help="minimum match score to cite a source (default 3)")
    ap.add_argument("--max-cites", type=int, default=3, help="most policy sections and most evidence files cited per answer (default 3)")
    ap.add_argument(
        "--fail-on",
        choices=["not-assessable", "contradicted", "none"],
        default="not-assessable",
        help="exit 1 when a question has this state or worse (default not-assessable)",
    )
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    ap.add_argument("--redact", action="store_true", help="replace e-mail addresses with stable tokens")
    ap.add_argument("--out", help="write the report to this file instead of stdout")
    ap.add_argument("--csv", help="also write the answers as CSV to this path")
    args = ap.parse_args(argv)
    if args.min_score < 1 or args.max_cites < 1:
        print("error: --min-score and --max-cites must be at least 1", file=sys.stderr)
        return 2
    if not args.evidence and not args.policies and not args.control_map:
        print("error: give at least one of --evidence, --policies or --control-map", file=sys.stderr)
        return 2
    try:
        questions = load_questions(Path(args.questionnaire))
        policies = load_policies(Path(args.policies) if args.policies else None)
        evidence, notes = load_evidence(Path(args.evidence) if args.evidence else None)
        cmap = load_control_map(Path(args.control_map) if args.control_map else None)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    answers = [draft(q, policies, evidence, cmap, args) for q in questions]
    rep = {
        "tool": "questionnaire",
        "questions": len(answers),
        "counts": {s: sum(1 for a in answers if a["state"] == s) for s in (SUPPORTED, CONTRADICTED, NOT_ASSESSABLE)},
        "sources": {"policy_sections": len(policies), "evidence_files": len(evidence), "controls": len(cmap)},
        "notes": notes,
        "answers": answers,
        "disclaimer": DISCLAIMER,
    }
    text = scrub(json.dumps(rep, indent=2, ensure_ascii=False) if args.json else render(rep), args.redact)
    try:
        if args.csv:
            Path(args.csv).write_text(scrub(answers_csv(answers), args.redact), encoding="utf-8", newline="")
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
        else:
            sys.stdout.write(text + "\n")
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2
    bad = {"not-assessable": (CONTRADICTED, NOT_ASSESSABLE), "contradicted": (CONTRADICTED,), "none": ()}[args.fail_on]
    return int(any(a["state"] in bad for a in answers))


if __name__ == "__main__":
    sys.exit(main())
