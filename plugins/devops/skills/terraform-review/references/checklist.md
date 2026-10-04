# Terraform review checklist

## 1. State and backend

| # | Check | Severity if failed |
|---|---|---|
| 1.1 | Remote backend with locking (S3 with DynamoDB or lockfile, GCS, Azure Blob, Terraform Cloud); no local state for shared infrastructure | blocker |
| 1.2 | State bucket is versioned, encrypted and not public; access limited to the CI role and operators | blocker |
| 1.3 | One state per environment or per blast radius; a root module that manages everything is a single point of failure | major |
| 1.4 | No `terraform import` or state surgery left undocumented | minor |

## 2. Pinning

| # | Check | Severity if failed |
|---|---|---|
| 2.1 | `required_version` set (`~> 1.9`) | major |
| 2.2 | Every provider has a `version` constraint and `.terraform.lock.hcl` is committed | major (blocker in root modules) |
| 2.3 | Modules pinned: registry `version = "x.y.z"`, git `?ref=<tag or sha>`; never a branch | major |
| 2.4 | AMIs, images and chart versions pinned, not `latest` or a data source with `most_recent = true` without a filter | major |

## 3. Inputs and outputs

| # | Check | Severity if failed |
|---|---|---|
| 3.1 | Every variable has `type` and `description`; dangerous ones have `validation` (CIDR shape, allowed instance sizes, environment enum) | major |
| 3.2 | Sensitive inputs marked `sensitive = true`; no defaults for secrets | major |
| 3.3 | Outputs have descriptions; sensitive outputs marked | minor |
| 3.4 | No `variable` whose default is a production value (account id, region, domain) in a reusable module | minor |

## 4. Secrets

| # | Check | Severity if failed |
|---|---|---|
| 4.1 | No literal passwords, keys or tokens in `.tf` or committed `.tfvars` (scan with `secrets-hygiene`) | blocker |
| 4.2 | Secrets come from a secret manager data source or are generated (`random_password`) and stored in one, never in outputs or state in plain form where avoidable | major |
| 4.3 | `.tfvars` with real values and `*.tfstate*` are in `.gitignore` | major |

## 5. Exposure

| # | Check | Severity if failed |
|---|---|---|
| 5.1 | No ingress from `0.0.0.0/0` or `::/0` except on 80/443 of a load balancer that is meant to be public | blocker |
| 5.2 | Storage buckets block public access; no `acl = "public-read"` unless the bucket is a static site by design | blocker |
| 5.3 | Databases, caches and queues have `publicly_accessible = false` and sit in private subnets | blocker |
| 5.4 | IAM: no `"Action": "*"` with `"Resource": "*"`; roles are per workload; no long-lived user keys where a role works | major |
| 5.5 | Kubernetes and container services: no privileged tasks, no host networking | major |

## 6. Encryption and logging

| # | Check | Severity if failed |
|---|---|---|
| 6.1 | Encryption at rest on volumes, databases, buckets, queues (customer-managed keys where policy requires) | major |
| 6.2 | TLS enforced in transit (`require_ssl`, HTTPS-only listeners, `transit_encryption_enabled`) | major |
| 6.3 | Access logs on load balancers and buckets; flow logs on VPCs; audit logs on the account | major |
| 6.4 | Backups and retention set on stateful resources (`backup_retention_period`, versioning, snapshots) | major |

## 7. Lifecycle

| # | Check | Severity if failed |
|---|---|---|
| 7.1 | `lifecycle { prevent_destroy = true }` on databases, buckets with data, DNS zones, KMS keys | major |
| 7.2 | `deletion_protection` and `skip_final_snapshot = false` on databases | major |
| 7.3 | Renames use `moved {}` blocks, not destroy and recreate | major |
| 7.4 | `create_before_destroy` on resources behind a dependency that cannot be down (certificates, launch templates) | minor |
| 7.5 | `ignore_changes` used only with a comment explaining what else manages the attribute | minor |

## 8. Structure and hygiene

| # | Check | Severity if failed |
|---|---|---|
| 8.1 | `terraform fmt` clean; `validate` passes; `tflint` passes | minor |
| 8.2 | Tags or labels on every resource (owner, environment, cost centre) via `default_tags` where supported | minor |
| 8.3 | `count` versus `for_each`: `for_each` keyed by stable names so removing one item does not shift the others | major |
| 8.4 | No provisioners (`local-exec`, `remote-exec`) where a native resource or user data would do | minor |
| 8.5 | Module interface small: inputs for what varies, sensible defaults, no pass-through of the whole provider configuration | minor |
