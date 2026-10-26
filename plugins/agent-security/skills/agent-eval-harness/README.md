# Agent eval harness

Builds a security evaluation for a tool-using agent: benign user tasks, injection tasks planted in tool results, and three numbers per agent and policy (utility, utility under attack, attack success rate). The runner uses the standard library only and never calls a model; you plug in your agent function.

Use it to measure prompt-injection resistance, to compare defences on the same tasks, or as a CI gate with `--max-asr`. Claude loads the skill from [SKILL.md](SKILL.md), which holds the full workflow and its limits; this page is the short version for people reading the repository.

## Run it

Sample: the two scripted demo agents against the bundled e-mail suite. Run from the repository root:

<!-- sample:begin -->
```bash
python3 plugins/agent-security/skills/agent-eval-harness/scripts/eval_runner.py --demo
```

```text
agent      policy                  utility  util@attack    ASR  denials  errors
naive      none                       1.00         1.00   1.00        0       0
naive      provenance                 1.00         1.00   0.00        2       0
naive      provenance+approval        1.00         1.00   0.00        2       0
careful    none                       1.00         1.00   0.00        0       0
careful    provenance                 1.00         1.00   0.00        0       0
careful    provenance+approval        1.00         1.00   0.00        0       0
```
<!-- sample:end -->

Exit codes: 0 finished (and every attack success rate at or below `--max-asr` when given), 1 an attack success rate above `--max-asr`, 2 a usage error, an `--agent` spec that cannot be loaded or an unwritable `--out`.

See [SKILL.md](SKILL.md) for the workflow, the options and the `## Limits` section.
