#!/usr/bin/env python3
"""Draft short control narratives from a control map, with an inline citation on every sentence that states evidence.

Usage:
  narrative.py <control-map.json> --control A.8.15 [--control A.8.32 ...] [--out narrative.md]
  narrative.py <control-map.json> --all

<control-map.json> is the JSON written by control_map.py (--out or --json). The draft uses only what the map holds:
each control's paraphrased topic, its state, the cited evidence (file, field, value) and its gaps. Nothing is
inferred beyond them.

Every sentence that reports evidence ends with a citation in the form [evidence: <file>#<field>], where file and field
are exactly as the control map cites them. Gaps become open items marked "not assessable from this pack". The draft
starts with the disclaimer that it is preparation for a human assessor and not an opinion or attestation.

Run narrative_lint.py on the draft, and again after any human edit, before it goes to the assessor.

Exit codes: 0 draft written, 2 bad input (unreadable map, unknown control). Nothing here calls any API.
"""
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _evidence import (  # noqa: E402
    CONTRADICTED,
    DISCLAIMER,
    SUPPORTED,
    InputError,
    add_common_args,
    as_of_datetime,
    dumps,
    load_json,
    redact,
    short,
)

LABELS = {"iso27001": "ISO/IEC 27001:2022 Annex A", "soc2": "SOC 2 Trust Services Criteria"}


def load_map(path: str) -> dict:
    data = load_json(Path(path))
    if not isinstance(data, dict) or not isinstance(data.get("controls"), list) or data.get("framework") not in LABELS:
        raise InputError(f"{path}: not a control map written by control_map.py (--out or --json)")
    return data


def code(value) -> str:
    """Quote an evidence value as inline code; export text is data, so backticks inside it are neutralised."""
    return "`" + short(value, 120).replace("`", "'").replace("\n", " ") + "`"


def cite(c: dict) -> str:
    return f"[evidence: {c['file']}#{c['field']}]"


def sentence_for(check: dict, c: dict) -> str:
    what = f'For the check "{check["describes"] or check["id"]}", ' if check.get("describes") or check.get("id") else ""
    base = f"{what}the export {c['file']} records {c['field']} as {code(c.get('value'))}"
    if check["state"] == CONTRADICTED:
        exp = c.get("expected")
        return base + (f", where the mapping expects {code(exp)}" if exp else "") + f" {cite(c)}."
    return base + f" {cite(c)}."


def control_section(ctrl: dict) -> list[str]:
    lines = [f"## {ctrl['id']}", "", f"Topic (paraphrase): {ctrl['topic'].rstrip('.')}.", ""]
    sentences = []
    for check in ctrl.get("checks") or []:
        for c in check.get("citations") or []:
            sentences.append(sentence_for(check, c))
    cites = " ".join(dict.fromkeys(cite(c) for c in ctrl.get("citations") or []))
    if ctrl["state"] == SUPPORTED:
        sentences.append(f"Taken together, the cited exports support every check mapped to this topic {cites}.")
    elif ctrl["state"] == CONTRADICTED:
        bad = [c for chk in ctrl.get("checks") or [] if chk["state"] == CONTRADICTED for c in chk.get("citations") or []]
        sentences.append("At least one cited export contradicts a check mapped to this topic "
                         + " ".join(dict.fromkeys(cite(c) for c in bad)) + ".")
    else:
        sentences.append("This topic is not assessable from the exports in this pack alone.")
    lines.append(" ".join(sentences))
    lines.append("")
    if ctrl.get("gaps"):
        lines.append("Open items for the assessor:")
        lines.append("")
        lines += [f"- Not assessable from this pack: {g}" for g in ctrl["gaps"]]
        lines.append("")
    return lines


def draft(cmap: dict, control_ids: list[str] | None, drafted: datetime) -> str:
    by_id = {c["id"]: c for c in cmap["controls"]}
    if control_ids:
        unknown = [c for c in control_ids if c not in by_id]
        if unknown:
            raise InputError(f"control(s) not in the control map: {', '.join(unknown)}; available: {', '.join(by_id)}")
        chosen = [by_id[c] for c in control_ids]
    else:
        chosen = list(by_id.values())
    lines = [f"# Draft control narratives: {LABELS[cmap['framework']]} identifiers", "", f"> {DISCLAIMER}", "",
             f"Drafted {drafted:%Y-%m-%d} from the control map of the evidence pack at {cmap.get('pack', '?')} "
             f"(pack built {cmap.get('pack_built_at', '?')}, map evaluated {cmap.get('as_of', '?')}). "
             "Topics are paraphrases written for this pack, not the framework's text. "
             "Each citation names a file inside the pack and the field read from it.", ""]
    for ctrl in chosen:
        lines += control_section(ctrl)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="narrative.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("control_map", help="control map JSON from control_map.py")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--control", action="append", help="control identifier to draft (repeatable), for example A.8.15 or CC8.1")
    group.add_argument("--all", action="store_true", help="draft every control in the map")
    ap.add_argument("--out", help="write the Markdown draft to this file")
    add_common_args(ap, fail_on=False)
    args = ap.parse_args(argv)
    try:
        cmap = load_map(args.control_map)
        if args.redact:
            cmap = redact(cmap)
        text = draft(cmap, None if args.all else args.control, as_of_datetime(args.as_of) if args.as_of else datetime.now(UTC))
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    if args.json:
        print(dumps({"framework": cmap["framework"], "controls": args.control or [c["id"] for c in cmap["controls"]],
                     "markdown": text, "disclaimer": DISCLAIMER}))
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
