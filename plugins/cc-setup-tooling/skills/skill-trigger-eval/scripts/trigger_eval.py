#!/usr/bin/env python3
"""trigger_eval.py: score skill descriptions against labelled prompts with transparent lexical rules.

This is a proxy. The host decides which skill to load with a language model reading every description; this script
only measures word and phrase overlap, so it is useful for comparing two wordings and spotting prompts a description
plainly misses or plainly attracts, not for predicting the host's choice.

Input:
  * a prompt set, YAML or JSON, keyed by skill name:

        decision-log:
          should_trigger:
            - "Write down that we decided to keep build logs for 30 days"
          should_not_trigger:
            - "Write an architecture decision record for the database move"

  * the descriptions: --skill PATH (repeatable; a SKILL.md, a skill folder or a folder of skills), or --compare OLD
    NEW (two SKILL.md files, or text files holding just the description) for two versions of one skill.

Scoring, per prompt and skill (words are lowercased, stop words dropped, simple suffixes stripped):
  coverage  share of the prompt's words found in the description outside its "Not ..." sentences
  bigram    share of the prompt's adjacent word pairs found in the description
  phrase    1 when every word of a quoted trigger phrase in the description is in the prompt, else the best word
            overlap (Jaccard) with a phrase when it is at least 0.5, else 0
  not_for   share of the prompt's words that appear only in the description's "Not ..." sentences
  score = 0.5 * coverage + 0.2 * bigram + 0.5 * phrase - 0.5 * not_for; the skill triggers when score >= --threshold.

Per skill it reports true and false positives and negatives, precision and recall, and every misjudged prompt with its
components. --cross also counts each skill's should_trigger prompts as should_not_trigger for the other skills.

Exit codes: 0 every skill meets --min-precision and --min-recall (with --compare: the new version is no worse on
either), 1 otherwise, 2 bad input (unreadable prompt set, no description found, no prompts for the skills given).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _skillmd  # noqa: E402

STOP = set(
    "a an and are as at be but by can do does for from has have how i if in into is it its me my of on or our so "
    "that the their them then there these this those to up us was we what when where which who why will with you "
    "your please could would should can't don't it's i'm let's just also any all some get got make sure use using "
    "used want need help not did about".split()
)
WEIGHTS = {"coverage": 0.5, "bigram": 0.2, "phrase": 0.5, "not_for": -0.5}
KEYS = {"should_trigger": "pos", "should-trigger": "pos", "should_not_trigger": "neg", "should-not-trigger": "neg"}


class InputError(Exception):
    """Bad input: the message is printed and the script exits 2."""


def stem(word: str) -> str:
    w = word.lower().removesuffix("'s")
    if len(w) > 5 and w.endswith("ing"):
        return w[:-3]
    if len(w) > 4 and w.endswith("ies"):
        return w[:-3] + "y"
    if len(w) > 4 and re.search(r"(?:x|z|ch|sh|ss)es$", w):
        return w[:-2]
    if len(w) > 4 and w.endswith("ed"):
        return w[:-2]
    if len(w) > 3 and w.endswith("s") and not w.endswith("ss"):
        return w[:-1]
    return w


def words(text: str) -> list[str]:
    return [stem(w) for w in re.findall(r"[a-z0-9]+(?:'[a-z]+)?", text.lower()) if w not in STOP and len(w) > 1]


def bigrams(seq: list[str]) -> set[tuple[str, str]]:
    return set(zip(seq, seq[1:], strict=False))


def profile(description: str) -> dict:
    sentences = re.split(r"(?<=[.!?])\s+", description.strip())
    neg_text = " ".join(s for s in sentences if s.startswith("Not "))
    pos_text = " ".join(s for s in sentences if not s.startswith("Not "))
    pos = words(pos_text)
    return {
        "words": set(pos),
        "bigrams": bigrams(pos),
        "not_for": set(words(neg_text)) - set(pos),
        "phrases": [set(words(p)) for p in _skillmd.quoted_phrases(pos_text) if words(p)],
    }


def score(prompt: str, prof: dict) -> dict:
    seq = words(prompt)
    pw = set(seq)
    if not pw:
        return {"coverage": 0.0, "bigram": 0.0, "phrase": 0.0, "not_for": 0.0, "score": 0.0}
    coverage = len(pw & prof["words"]) / len(pw)
    pb = bigrams(seq)
    bigram = len(pb & prof["bigrams"]) / len(pb) if pb else 0.0
    phrase = 0.0
    for ph in prof["phrases"]:
        if ph <= pw:
            phrase = 1.0
            break
        jac = len(ph & pw) / len(ph | pw)
        if jac >= 0.5:
            phrase = max(phrase, jac)
    not_for = len(pw & prof["not_for"]) / len(pw)
    parts = {"coverage": coverage, "bigram": bigram, "phrase": phrase, "not_for": not_for}
    total = sum(WEIGHTS[k] * v for k, v in parts.items())
    return {k: round(v, 4) for k, v in {**parts, "score": total}.items()}


def unquote(item: str) -> str:
    item = item.strip()
    if item.startswith('"'):
        return _skillmd.decode_double(item)[0]
    if item.startswith("'"):
        return _skillmd.decode_single(item)[0]
    return re.split(r"\s+#", item, maxsplit=1)[0].strip()


def read_prompts(path: Path) -> dict[str, dict[str, list[str]]]:
    if not path.is_file():
        raise InputError(f"{path}: prompt set not found")
    text = _skillmd.read_text(path)
    if text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InputError(f"{path}: invalid JSON: {exc}") from exc
    else:
        data, skill, key = {}, None, None
        for number, line in enumerate(text.replace("\r\n", "\n").split("\n"), start=1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            body = line.strip()
            if indent == 0 and re.fullmatch(r"[A-Za-z0-9_.-]+:", body):
                skill, key = body[:-1], None
                data[skill] = {}
            elif skill and re.fullmatch(r"[a-z_-]+:", body) and indent > 0:
                key = body[:-1]
                data[skill].setdefault(key, [])
            elif skill and key and body.startswith("- "):
                data[skill][key].append(unquote(body[2:]))
            else:
                raise InputError(f"{path}:{number}: expected 'skill:', 'should_trigger:' or '- prompt'")
    if not isinstance(data, dict) or not data:
        raise InputError(f"{path}: no skills in the prompt set")
    out: dict[str, dict[str, list[str]]] = {}
    for skill, groups in data.items():
        if not isinstance(groups, dict):
            raise InputError(f"{path}: entry {skill!r} must map should_trigger and should_not_trigger to lists")
        out[skill] = {"pos": [], "neg": []}
        for key, prompts in groups.items():
            if key not in KEYS or not isinstance(prompts, list) or not all(isinstance(p, str) for p in prompts):
                raise InputError(f"{path}: {skill}.{key} must be should_trigger or should_not_trigger with a list")
            out[skill][KEYS[key]] += [p for p in prompts if p.strip()]
    return out


def read_description(path: Path) -> tuple[str | None, str]:
    text = _skillmd.read_text(path)
    fm = _skillmd.parse(text)
    if fm.closed:
        return (fm.text("name") or path.parent.name), fm.text("description")
    return None, text.strip()


def evaluate(name: str, description: str, prompts: dict[str, list[str]], threshold: float) -> dict:
    prof = profile(description)
    rows = []
    for label, items in (("pos", prompts["pos"]), ("neg", prompts["neg"]), ("cross", prompts.get("cross", []))):
        for p in items:
            s = score(p, prof)
            rows.append({"prompt": p, "label": label, "triggered": s["score"] >= threshold, **s})
    tp = sum(r["triggered"] for r in rows if r["label"] == "pos")
    fn = sum(not r["triggered"] for r in rows if r["label"] == "pos")
    fp = sum(r["triggered"] for r in rows if r["label"] != "pos")
    tn = sum(not r["triggered"] for r in rows if r["label"] != "pos")
    return {
        "skill": name,
        "description_chars": len(description),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "prompts": rows,
    }


def passes(r: dict, min_p: float, min_r: float) -> bool:
    return (r["precision"] is None or r["precision"] >= min_p) and (r["recall"] is None or r["recall"] >= min_r)


def fmt(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.2f}"


def render(rep: dict) -> str:
    out = ["# Skill trigger evaluation (lexical proxy)", ""]
    out.append(
        f"Threshold {rep['threshold']}; score = 0.5 coverage + 0.2 bigram + 0.5 phrase - 0.5 not_for. "
        "Lexical overlap only: the host chooses skills with a model, so treat this as a comparison aid."
    )
    out += ["", "| Skill | Precision | Recall | TP | FN | FP | TN | Verdict |", "|---|---|---|---|---|---|---|---|"]
    for r in rep["results"]:
        verdict = f"{r['version']} version" if "version" in r else "ok" if r["ok"] else "below target"
        out.append(
            f"| {r['skill']} | {fmt(r['precision'])} | {fmt(r['recall'])} | {r['tp']} | {r['fn']} | {r['fp']} | "
            f"{r['tn']} | {verdict} |"
        )
    if rep.get("compare"):
        c = rep["compare"]
        out += ["", f"Compare: new version {'is no worse' if c['ok'] else 'is worse'} than the old one."]
        if c["flips"]:
            out += ["", "## Prompts whose result changed", ""]
            out += [f'- {f["label"]} "{f["prompt"]}": {f["old"]} -> {f["new"]}' for f in c["flips"]]
    out += ["", "## Misjudged prompts", ""]
    any_row = False
    for r in rep["results"]:
        for p in r["prompts"]:
            wrong = (p["label"] == "pos") != p["triggered"]
            if wrong:
                any_row = True
                kind = "missed" if p["label"] == "pos" else f"false trigger ({p['label']})"
                out.append(
                    f'- {r["skill"]}{" " + r["version"] if "version" in r else ""}: {kind} "{p["prompt"]}" '
                    f"(score {p['score']}: coverage {p['coverage']}, bigram {p['bigram']}, phrase {p['phrase']}, "
                    f"not_for {p['not_for']})"
                )
    if not any_row:
        out.append("None.")
    for w in rep["warnings"]:
        out.append(f"\nWarning: {w}")
    out.append("")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trigger_eval.py",
        description="Score skill descriptions against labelled should-trigger and should-not-trigger prompts with "
        "transparent lexical rules, per skill, or compare two versions of one description.",
        epilog="Exit codes: 0 targets met (or new version no worse), 1 otherwise, 2 bad input.",
    )
    p.add_argument("prompts", help="prompt set, YAML or JSON, keyed by skill name")
    p.add_argument("--skill", action="append", default=[], help="SKILL.md, skill folder or folder of skills")
    p.add_argument("--compare", nargs=2, metavar=("OLD", "NEW"), help="two versions of one skill's description")
    p.add_argument("--name", default=None, help="skill name for --compare (default: the name in NEW)")
    p.add_argument("--threshold", type=float, default=0.35, help="score at which a skill triggers (default 0.35)")
    p.add_argument("--min-precision", type=float, default=0.8, help="target precision (default 0.8)")
    p.add_argument("--min-recall", type=float, default=0.8, help="target recall (default 0.8)")
    p.add_argument("--cross", action="store_true", help="use other skills' should_trigger prompts as negatives")
    p.add_argument("--json", action="store_true", help="print the computed data as JSON instead of Markdown")
    p.add_argument("--out", default=None, help="write the report to this file instead of standard output")
    return p


def run(args: argparse.Namespace) -> tuple[dict, int]:
    prompts = read_prompts(Path(args.prompts))
    rep: dict = {"threshold": args.threshold, "results": [], "warnings": []}
    if args.compare:
        old_p, new_p = (Path(x) for x in args.compare)
        for p in (old_p, new_p):
            if not p.is_file():
                raise InputError(f"{p}: not found")
        new_name, new_desc = read_description(new_p)
        _, old_desc = read_description(old_p)
        name = args.name or new_name
        if not name or name not in prompts:
            raise InputError(f"no prompts for {name!r} in the prompt set; pass --name")
        if not old_desc or not new_desc:
            raise InputError("an empty description cannot be compared")
        old = evaluate(name, old_desc, prompts[name], args.threshold)
        new = evaluate(name, new_desc, prompts[name], args.threshold)
        old["version"], new["version"] = "old", "new"

        def worse(a: float | None, b: float | None) -> bool:
            return (b or 0.0) < (a or 0.0)

        ok = not worse(old["precision"], new["precision"]) and not worse(old["recall"], new["recall"])
        flips = [
            {"prompt": a["prompt"], "label": a["label"], "old": a["triggered"], "new": b["triggered"]}
            for a, b in zip(old["prompts"], new["prompts"], strict=True)
            if a["triggered"] != b["triggered"]
        ]
        rep["results"] = [old, new]
        rep["compare"] = {"ok": ok, "flips": flips}
        return rep, 0 if ok else 1
    if not args.skill:
        raise InputError("give --skill PATH (repeatable) or --compare OLD NEW")
    paths = [Path(s) for s in args.skill]
    for p in paths:
        if not p.exists():
            raise InputError(f"{p}: not found")
    descriptions: dict[str, str] = {}
    for f in _skillmd.find_skill_files(paths):
        name, desc = read_description(f)
        if name and desc:
            descriptions[name] = desc
    evaluated = sorted(set(descriptions) & set(prompts))
    if not evaluated:
        raise InputError("none of the skills found has prompts in the prompt set")
    for name in sorted(set(prompts) - set(descriptions)):
        rep["warnings"].append(f"prompts for {name!r} but no description was found")
    for name in sorted(set(descriptions) - set(prompts)):
        rep["warnings"].append(f"{name!r} has a description but no prompts")
    for name in evaluated:
        groups = dict(prompts[name])
        if args.cross:
            groups["cross"] = [p for other in evaluated if other != name for p in prompts[other]["pos"]]
        r = evaluate(name, descriptions[name], groups, args.threshold)
        r["ok"] = passes(r, args.min_precision, args.min_recall)
        rep["results"].append(r)
    return rep, 0 if all(r["ok"] for r in rep["results"]) else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rep, code = run(args)
    except InputError as exc:
        print(f"trigger_eval.py: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(rep, indent=2, sort_keys=True) + "\n" if args.json else render(rep)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
