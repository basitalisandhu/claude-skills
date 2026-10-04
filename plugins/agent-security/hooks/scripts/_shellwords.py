"""Tiny shell-command segmenter shared by the agent-security hooks. Standard library only.

It is deliberately conservative: it does not try to be a full shell parser. It splits a command line
into segments at control operators (| || && ; & newline and subshell parentheses), strips leading
VAR=value assignments and common wrappers (sudo, env, command, exec, nohup, time, nice, timeout,
xargs), and recurses into `sh -c "..."`, `bash -c`, `zsh -c` and `eval "..."` strings and into
command substitutions (`$(...)` and backticks, quoted or not) so that a guard cannot be dodged by
one level of quoting.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field

CONTROL_RE = re.compile(r"^[|&;()]+$")
WRAPPERS_WITH_FLAGS = {"sudo", "command", "exec", "builtin", "nohup", "time", "timeout", "nice", "ionice", "doas", "xargs", "stdbuf", "unbuffer", "watch"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox"}


@dataclass
class Segment:
    """One simple command: its program (basename, lower-cased), its arguments, the operator that
    preceded it (``|``, ``&&``, ``;`` ... or ``""`` for the first segment) and the raw text."""

    program: str
    args: list[str]
    operator: str
    raw: str
    env_assignments: list[str] = field(default_factory=list)


def tokenize(command: str) -> list[str]:
    """Shell-like tokens with control operators kept as separate tokens. Falls back to a regex
    split when the input has unbalanced quotes, so the hook still sees something."""
    text = command.replace("\r\n", "\n").replace("\n", " ; ")
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars="|&;()<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        tokens = []
        for piece in re.split(r"(\|\||&&|[|;&()])", text):
            piece = piece.strip()
            if not piece:
                continue
            if CONTROL_RE.match(piece):
                tokens.append(piece)
            else:
                tokens.extend(piece.replace('"', " ").replace("'", " ").split())
    return tokens


def _strip_wrappers(words: list[str]) -> tuple[list[str], list[str]]:
    """Remove leading assignments and wrapper programs. Returns (remaining words, assignments)."""
    assignments: list[str] = []
    i = 0
    while i < len(words):
        w = words[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w):
            assignments.append(w)
            i += 1
            continue
        base = os.path.basename(w).lower()
        if base in WRAPPERS_WITH_FLAGS:
            i += 1
            # skip the wrapper's own flags and, for timeout/nice/sudo -u, their values
            while i < len(words):
                nxt = words[i]
                if nxt.startswith("-"):
                    if base in {"sudo", "doas"} and nxt in {"-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U"}:
                        i += 2
                    elif base == "nice" and nxt == "-n":
                        i += 2
                    elif base == "timeout" and nxt in {"-s", "-k", "--signal", "--kill-after"}:
                        i += 2
                    else:
                        i += 1
                    continue
                if base == "timeout" and re.match(r"^\d+(\.\d+)?[smhd]?$", nxt):
                    i += 1
                    continue
                break
            continue
        if base == "env":
            # `env` with a command after it is a wrapper; bare `env` is a dump (handled by the caller)
            j = i + 1
            while j < len(words) and (words[j].startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[j])):
                if words[j] in {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}:
                    j += 2
                else:
                    j += 1
            if j < len(words):
                i = j
                continue
        break
    return words[i:], assignments


def command_substitutions(text: str) -> list[str]:
    """Inner commands of every `$(...)` and `` `...` `` in the text, quoted or not. Nested ones are
    found again when the caller recurses on the inner string."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("$(", i):
            depth, j = 1, i + 2
            while j < n and depth:
                depth += 1 if text[j] == "(" else -1 if text[j] == ")" else 0
                j += 1
            out.append(text[i + 2:j - 1] if depth == 0 else text[i + 2:])
            i = j
        elif text[i] == "`":
            j = text.find("`", i + 1)
            j = n if j < 0 else j
            out.append(text[i + 1:j])
            i = j + 1
        else:
            i += 1
    return [x for x in out if x.strip()]


def segments(command: str, _depth: int = 0) -> list[Segment]:
    """Split a command line into simple-command segments, recursing into quoted sub-shells and
    command substitutions."""
    tokens = tokenize(command)
    out: list[Segment] = []
    if _depth < 3:
        for inner in command_substitutions(command):
            out.extend(segments(inner, _depth + 1))
    current: list[str] = []
    operator = ""

    def flush(op: str) -> None:
        nonlocal current
        if current:
            words, assignments = _strip_wrappers(current)
            raw = " ".join(current)
            if words:
                prog = os.path.basename(words[0]).lower()
                out.append(Segment(prog, words[1:], op, raw, assignments))
                if _depth < 3:
                    out.extend(_nested(prog, words[1:], _depth))
            else:
                out.append(Segment("", [], op, raw, assignments))
        current = []

    for tok in tokens:
        if CONTROL_RE.match(tok):
            flush(operator)
            operator = tok
        elif tok in {">", ">>", "<", "<<", "<<<", ">&", "<&", "&>", ">|", "<>"}:
            # redirections: keep the operator so callers can see them, as a plain token
            current.append(tok)
        else:
            current.append(tok)
    flush(operator)
    return out


def _nested(prog: str, args: list[str], depth: int) -> list[Segment]:
    """Return segments parsed out of `sh -c '...'`, `eval '...'` and similar."""
    nested: list[Segment] = []
    if prog in SHELLS:
        for i, a in enumerate(args):
            if a in {"-c", "-lc", "-ic", "-ec", "-euc", "-exc", "-xc"} and i + 1 < len(args):
                nested.extend(segments(args[i + 1], depth + 1))
                break
    elif prog in {"eval", "source", "."}:
        if prog == "eval" and args:
            nested.extend(segments(" ".join(args), depth + 1))
    return nested


def basename_of(token: str) -> str:
    return os.path.basename(token.replace("\\", "/")).lower()


def expand_home(token: str) -> str:
    return re.sub(r"^~(?=/|$)|\$HOME(?=/|$)|\$\{HOME\}(?=/|$)", "~", token)
