# Triage guide

## Per family (upstream ids, with bundled counterparts in brackets)

| Family | Usually a true positive when | Usually a false positive when | Fix |
|---|---|---|---|
| `llm-output-to-exec-eval`, `llm-output-to-os-system`, `llm-output-to-subprocess`, `llm-output-to-child-process`, `llm-output-to-eval-function` [`agentic.*.model-output-to-exec`] | The executed string comes from a completion, even through a parser that only strips code fences | The variable name matched a source pattern but holds a constant; exec runs in an isolated sandbox with no credentials and no network (then: accepted risk, name the sandbox) | Sandbox with no credentials; replace exec with structured output and a fixed set of operations |
| `agent-tool-param-to-shell`, `mcp-tool-param-to-shell` [`shell-true-with-interpolation`, `exec-with-template-literal`] | The tool is callable by the model and the parameter reaches a shell string | Parameter is validated against an allowlist before the call (add the validator to `pattern-sanitizers` upstream) | argv arrays, no shell; fixed executable with typed arguments; approval for side effects |
| `agent-tool-param-to-file-path`, `mcp-tool-param-to-file-path`, `llm-output-to-file-path` | The path is not canonicalised and confined to a root | `realpath` plus prefix check runs first | Resolve, then check `startsWith(root + sep)`; deny `..` and symlink escapes |
| `llm-output-to-sql` | Query text is concatenated from model output | A parameterised query builder is used and the rule matched a column name constant | Parameters or a query builder; allowlist tables and columns |
| `llm-output-to-http-request`, `llm-output-to-fetch` [`tool-fetches-model-controlled-url`] | The URL is model-chosen and not restricted | A sanitiser the rule does not know runs first | Host allowlist; resolve and reject private and link-local addresses; no redirects; timeouts; size cap |
| `llm-output-to-html`, `llm-output-to-innerhtml` | Model text is rendered without encoding | Output passes through a sanitiser or a templating engine with auto-escaping | Encode; render as text; strip images and links from untrusted output |
| `user-input-in-system-prompt` | The interpolated variable carries user text, documents or tool output | It is a static config value (app name, date) | Keep the system prompt static; pass variable content in a user or tool message with delimiters |
| `fastmcp-bind-all-interfaces`, `fastmcp-http-transport-without-auth`, `mcp-http-transport-without-auth` [`mcp-server-binds-all-interfaces`] | The process is reachable from other hosts without auth | Inside a container whose network is isolated and the port is not published (accepted risk, note it) | Bind 127.0.0.1; add auth and Origin validation before exposing |
| `langchain-dangerous-tools`, `langchain-allow-dangerous-code`, `langchain-allow-dangerous-requests` | The flag or tool is on in a path the model drives | Test code or a sandboxed evaluation harness | Remove the flag; replace the tool with a typed, scoped one |
| `pickle-load-model-file`, `torch-load-without-weights-only`, `langchain-allow-dangerous-deserialization`, `transformers-trust-remote-code`, `yaml-unsafe-load` [`pickle-model-load`] | The artefact or file comes from a hub, a bucket or a user | The file is produced and consumed by the same trusted pipeline | safetensors; `weights_only=True`; `yaml.safe_load`; signature verification |
| `hardcoded-llm-api-key`, `llm-api-key-logged`, `api-key-in-command-line-arg` | Always | Test fixtures with obvious placeholders | Environment or a credential broker lease; redact logs; rotate the key |
| `agentic.config.*` (bundled only) | Always, these are configuration facts | Test fixtures that intentionally contain bad config (exclude the fixture directory) | See `agent-config-audit` recommendations |

## Severity mapping

| Semgrep severity | Report as | Why |
|---|---|---|
| ERROR | high (critical when reachable from an untrusted channel with shell, payments or cloud credentials) | Direct path to code execution or full bypass |
| WARNING | medium (high when combined with another finding on the same flow) | Needs an injected input or a second weakness |
| INFO | low | Hygiene |

## Suppressing

Only with the user's agreement and a reason that will still make sense in a year:

```python
subprocess.run(cmd, shell=True)  # nosemgrep: agentic-semgrep-rules.rules.python.permissions.agent-tool-param-to-shell -- cmd is an allowlisted constant chosen by index
```

Use the id exactly as Semgrep printed it (prefixed when run from a clone). Never suppress by excluding whole directories except test fixtures.

## CI

The upstream pack ships a GitHub Action that installs Semgrep, writes SARIF, uploads it to code scanning and fails on findings at or above a threshold:

```yaml
# .github/workflows/agent-security.yml
name: agent-security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: basitalisandhu/agentic-semgrep-rules@v1
        with:
          severity: ERROR        # fail at this level or above (INFO, WARNING, ERROR)
          upload-sarif: "true"
      - name: Agent configuration rules (bundled with agent-security-skills)
        run: |
          pip install semgrep==1.179.0
          git clone --depth 1 https://github.com/basitalisandhu/agent-security-skills /tmp/ass
          semgrep --metrics=off --config /tmp/ass/plugins/agent-security/skills/semgrep-agentic/rules/agentic-config.yaml --error \
            $(git ls-files '.claude/settings.json' '.mcp.json' '.cursor/mcp.json' '**/.mcp.json' 2>/dev/null) || true
```

Without the Action: `pip install semgrep==1.179.0` then `semgrep --config <clone>/rules --metrics=off --error --severity ERROR .` (drop `--severity ERROR` to fail on WARNING too).

## Writing a new rule

Contribute upstream (`rules/<language>/<category>/<rule-id>.yaml` with a fixture at `tests/<language>/<category>/<rule-id>.<ext>`; `make test`, `make validate`, `make smoke`), following `docs/rule-writing.md` there. Start from an incident, write the positive and negative fixtures first, prefer taint mode for "untrusted value reaches sink" rules and plain patterns for configuration and binding checks, and add `metadata` (`cwe`, `owasp`, `confidence`, `likelihood`, `impact`, `technology`, `references`). A rule with a failing fixture does not ship.
