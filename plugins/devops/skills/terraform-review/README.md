# terraform-review

Review Terraform or OpenTofu files (main.tf, modules, variables) against a checklist: state and backend safety, version pinning, typed and validated variables, secrets in variables, public exposure (open security groups, public buckets, 0.0.0.0/0), missing encryption and logging defaults, lifecycle and destroy protection.

Use it when asked to "review this Terraform" or other IaC files, or what in it is exposed to the internet.
Not for gating a saved plan before apply (terraform-apply-gate), cloud architecture from scratch, or Dockerfiles and manifests.

Claude follows [SKILL.md](SKILL.md); it is part of the `devops` plugin (`/plugin install devops@claude-dev-skills`).

## How it works

This skill has no script: Claude works through the procedure in SKILL.md and the reference file [`references/checklist.md`](references/checklist.md), and states what it could not check.

## Example requests

- "Review this Terraform before I apply it"
- "Is anything in main.tf exposed to the internet? Look at the security groups and buckets"
- "Check our OpenTofu modules for version pinning, state safety and missing validation on variables"

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
