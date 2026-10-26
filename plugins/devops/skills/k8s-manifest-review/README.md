# k8s-manifest-review

Review Kubernetes manifests (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Pods, Services, Secrets) with a bundled script for missing limits and probes, privileged or root containers, latest or mutable image tags, host namespaces, hostPath mounts, inline secrets and no seccomp, then write corrected, production-ready YAML.

Use it when asked to "review this Kubernetes YAML", to harden a Deployment, why a scanner flags privileged or hostPath, or to check a Helm chart's output.
Not for a Dockerfile (dockerfile-hardening) or cluster policy such as RBAC and admission control.

Claude follows [SKILL.md](SKILL.md); it is part of the `devops` plugin (`/plugin install devops@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/devops/skills/k8s-manifest-review/scripts/k8s_review.py tests/fixtures/k8s-manifest-review/deployment.yaml
```

Inside Claude Code the skill runs `k8s_review.py` from `${CLAUDE_PLUGIN_ROOT}/skills/k8s-manifest-review/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/k8s-manifest-review/` (synthetic data):

<!-- sample: --lines=30 plugins/devops/skills/k8s-manifest-review/scripts/k8s_review.py tests/fixtures/k8s-manifest-review/deployment.yaml -->
```text
k8s-manifest-review 0.1.0: 3 objects in 1 file(s), 20 findings critical=2, high=7, medium=6, low=3, info=2
  [critical] K8S-002 Deployment/web spec.containers[web].securityContext.privileged: Privileged container
      fix: Remove privileged: true; grant specific capabilities if a node-level feature is needed.
  [critical] K8S-008 Deployment/web spec.volumes[sock].hostPath: hostPath volume mounts /var/run/docker.sock from the node
      fix: Use a PersistentVolumeClaim, ConfigMap or emptyDir; hostPath gives the pod access to the node filesystem.
  [high    ] K8S-014 Deployment/web spec.containers[web].env[DB_PASSWORD]: Secret-looking env var with a literal value
      fix: Use valueFrom.secretKeyRef and keep the value out of the manifest.
  [high    ] K8S-007 Deployment/web spec.containers[web].image: Image nginx has no tag (resolves to latest)
      fix: Pin an immutable tag or a digest.
  [high    ] K8S-001 Deployment/web spec.containers[web].resources.limits.memory: No memory limit
      fix: Set resources.limits.memory so one container cannot evict its neighbours.
  [high    ] K8S-001 Deployment/web spec.containers[web].resources.requests: No cpu or memory request
      fix: Set resources.requests so the scheduler can place the pod and the QoS class is predictable.
  [high    ] K8S-006 Deployment/web spec.containers[web].securityContext.capabilities.add: Dangerous capabilities added: SYS_ADMIN
      fix: Remove them; most of these give root-equivalent access to the node.
  [high    ] K8S-003 Deployment/web spec.containers[web].securityContext.runAsNonRoot: Container may run as root
      fix: Set runAsNonRoot: true (and a runAsUser in the image or spec).
  [high    ] K8S-008 Deployment/web spec.hostNetwork: hostNetwork: true shares the node namespace
      fix: Remove it unless the workload is a node agent that needs it.
  [medium  ] K8S-009 Deployment/web spec.containers[web].livenessProbe: No livenessProbe
      fix: Add a liveness probe so a hung process is restarted.
  [medium  ] K8S-009 Deployment/web spec.containers[web].readinessProbe: No readinessProbe
      fix: Add a readiness probe so traffic is not routed before the process can serve it.
  [medium  ] K8S-004 Deployment/web spec.containers[web].securityContext.allowPrivilegeEscalation: allowPrivilegeEscalation not false
      fix: Set allowPrivilegeEscalation: false.
  [medium  ] K8S-006 Deployment/web spec.containers[web].securityContext.capabilities.drop: Capabilities not dropped
      fix: Set capabilities.drop: [ALL] and add back only what is needed (for example NET_BIND_SERVICE).
  [medium  ] K8S-005 Deployment/web spec.containers[web].securityContext.readOnlyRootFilesystem: Root filesystem is writable
      fix: Set readOnlyRootFilesystem: true and mount emptyDir volumes where the process writes.
  [medium  ] K8S-013 Secret/creds data: Secret manifest carries inline secret material
...
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
