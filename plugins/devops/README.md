# DevOps

Nine skills for shipping and operating software: Dockerfile hardening, GitHub Actions authoring and validation, Kubernetes manifest review, Terraform review, a Terraform apply gate, crontab diagnosis, .env key diffs, release notes from git history, and a semver advisor.

Find this when you search for: Docker image too big, CI pipeline timeout, terraform plan policy, prevent terraform destroy.

## Install

```text
/plugin marketplace add basitalisandhu/claude-dev-skills
/plugin install devops@claude-dev-skills
```

Skills then appear as `/devops:<skill>`. Scripts need Python 3.11 or newer on `PATH` as `python3`; they use the standard library only and make no network calls.

## Skills

| Skill | Triggers on | Produces |
|---|---|---|
| `dockerfile-hardening` | review, slim or write a Dockerfile | `dockerfile_lint.py` findings, pinned non-root multi-stage build |
| `github-actions-author` | add CI, review workflows, unpinned actions | `gha_lint.py` findings, least-privilege workflow from templates |
| `k8s-manifest-review` | review or harden Kubernetes YAML | `k8s_review.py` findings, restricted-baseline manifests |
| `terraform-review` | review Terraform code or a module | checklist findings, plan reading, rules to automate |
| `terraform-apply-gate` | can we apply this plan, pre-apply CI step | `terraform_apply_gate.py` allow, ask or block against a YAML policy |
| `cron-doctor` | cron job did not run, ran twice, wrong time | `cron_doctor.py` schedule explanations, next runs, fixes |
| `env-diff` | works locally fails in staging, onboarding config | `env_diff.py` missing, extra and empty keys (no values) |
| `release-notes` | release notes, GitHub release body | `release_notes.py` grouped Markdown, edited for readers |
| `semver-advisor` | is this breaking, major or minor | version decision with evidence per change |

Tests for every script live in the repository's `tests/` directory; run `python3 -m pytest -q` at the repository root.
