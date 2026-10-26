# regex-builder

Write and test regular expressions that match what they should and nothing else: a bundled script runs a pattern against labelled sample lines, shows each match and captured group, and warns on patterns that can backtrack catastrophically.

Use it when asked to "write a regex" (phone numbers, dates, ids), "why does my pattern not match", to "extract the id and amount from lines like" a sample, or to check a regex used on user input.
Not for parsing structured formats (JSON, HTML, URLs: use a parser) and not for full-text search.

Claude follows [SKILL.md](SKILL.md); it is part of the `data` plugin (`/plugin install data@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/data/skills/regex-builder/scripts/regex_tester.py "^(?P<user>[\w.+-]+)@(?P<domain>[\w-]+\.[\w.]+)$" --cases tests/fixtures/regex-builder/cases.txt
```

Inside Claude Code the skill runs `regex_tester.py` from `${CLAUDE_PLUGIN_ROOT}/skills/regex-builder/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/regex-builder/` (synthetic data):

<!-- sample: plugins/data/skills/regex-builder/scripts/regex_tester.py "^(?P<user>[\w.+-]+)@(?P<domain>[\w-]+\.[\w.]+)$" --cases tests/fixtures/regex-builder/cases.txt -->
```text
regex-tester 0.1.0: /^(?P<user>[\w.+-]+)@(?P<domain>[\w-]+\.[\w.]+)$/ (search), 2 groups named user, domain: 3 passed, 0 failed
  ok   [match   ] 'user@example.com': matched 'user@example.com' groups=['user', 'example.com']
  ok   [no-match] 'not-an-email': no match
  ok   [groups  ] 'bob@example.com': matched 'bob@example.com' groups=['bob', 'example.com'] expected {'user': 'bob', 'domain': 'example.com'}
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
