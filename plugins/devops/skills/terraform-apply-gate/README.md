# terraform-apply-gate

Decide whether a saved Terraform plan may be applied under the team's written rules: a bundled script checks the plan JSON against a small YAML policy (forbidden destroys by type, required tags, a replacement ceiling, protected names, allowed providers) and prints allow, ask or block with a reason per resource.

Use it when asked "can we apply this plan?", before an apply in CI or a hook, or when a plan shows deletes.
Not for reviewing Terraform code (terraform-review) and not for writing the change record.

Claude follows [SKILL.md](SKILL.md); it is part of the `devops` plugin (`/plugin install devops@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/devops/skills/terraform-apply-gate/scripts/terraform_apply_gate.py tests/fixtures/terraform-apply-gate/plan.json --policy tests/fixtures/terraform-apply-gate/policy.yml
```

Inside Claude Code the skill runs `terraform_apply_gate.py` from `${CLAUDE_PLUGIN_ROOT}/skills/terraform-apply-gate/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/terraform-apply-gate/` (synthetic data):

<!-- sample: plugins/devops/skills/terraform-apply-gate/scripts/terraform_apply_gate.py tests/fixtures/terraform-apply-gate/plan.json --policy tests/fixtures/terraform-apply-gate/policy.yml -->
```text
terraform-apply-gate 0.1.0: verdict BLOCK
plan: 1 to create, 0 to update, 1 to replace, 0 to delete, 0 unchanged
  [block] forbidden-destroy: aws_db_instance.prod: replace of type aws_db_instance is forbidden by 'aws_db_instance' (replace_because_cannot_update)
  [block] protected-name: aws_db_instance.prod: replace of a protected address (matches '*prod*') (replace_because_cannot_update)
  [ask] missing-tags: aws_s3_bucket.logs: missing required tags: environment
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
