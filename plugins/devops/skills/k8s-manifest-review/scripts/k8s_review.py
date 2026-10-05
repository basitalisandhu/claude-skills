#!/usr/bin/env python3
"""Review Kubernetes manifests for the settings that most often cause outages or security findings.

Checks (id, severity), applied to every container of every workload (Pod, Deployment, StatefulSet, DaemonSet,
ReplicaSet, Job, CronJob) and to the pod spec:
  K8S-001 high      no resources.limits (memory) / no resources.requests
  K8S-002 critical  securityContext.privileged: true
  K8S-003 high      runAsNonRoot not true at pod or container level
  K8S-004 medium    allowPrivilegeEscalation not false
  K8S-005 medium    readOnlyRootFilesystem not true
  K8S-006 medium    capabilities not dropped (drop: [ALL]); high when SYS_ADMIN, NET_ADMIN, SYS_PTRACE or ALL added
  K8S-007 high      image without a tag or with :latest
  K8S-008 high      hostNetwork, hostPID or hostIPC; hostPath volume (critical for /, /var/run/docker.sock, /etc, /proc)
  K8S-009 medium    no livenessProbe or readinessProbe (long-running workloads only)
  K8S-010 low       service account token automounted without a named serviceAccountName
  K8S-011 info      no metadata.namespace
  K8S-012 info      Service of type NodePort or LoadBalancer
  K8S-013 medium    Secret manifest with inline data or stringData (secret material in version control)
  K8S-014 high      container env var with a secret-looking name and a literal value
  K8S-015 low       no seccompProfile (RuntimeDefault)
  K8S-016 low       Deployment with one replica and no strategy (single point of failure)

Usage:
    k8s_review.py PATH [PATH ...] [--json] [--fail-on SEVERITY]      (files or directories of .yaml/.yml/.json)

Exit codes: 0 nothing at or above --fail-on (default: high), 1 otherwise, 2 bad input.
Standard library only (bundled minimal YAML reader). Read-only. No network.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _miniyaml import YAMLError, load_all  # noqa: E402

VERSION = "0.1.0"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
LONG_RUNNING = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL", "SYS_MODULE", "DAC_READ_SEARCH", "NET_RAW", "SYS_RAWIO"}
DANGEROUS_HOSTPATHS = ("/", "/var/run/docker.sock", "/run/docker.sock", "/etc", "/proc", "/sys", "/var/lib/kubelet", "/root", "/var/run/crio")
SECRET_KEY_RE = re.compile(r"(?i)(api[_-]?key|secret|token|passw(or)?d|credential|private[_-]?key|access[_-]?key)")


def collect(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files += sorted(x for x in p.rglob("*") if x.suffix in {".yaml", ".yml", ".json"} and x.is_file())
        elif p.is_file():
            files.append(p)
        else:
            raise FileNotFoundError(raw)
    return files


def pod_spec_of(doc: dict):
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    if kind in WORKLOADS:
        return ((spec.get("template") or {}).get("spec"))
    return None


def review_doc(path: Path, idx: int, doc) -> list[dict]:
    findings: list[dict] = []
    if not isinstance(doc, dict) or "kind" not in doc:
        return findings
    kind = doc.get("kind")
    meta = doc.get("metadata") or {}
    name = f"{kind}/{meta.get('name', '?')}"

    def add(fid, sev, where, title, fix):
        findings.append({"id": fid, "severity": sev, "file": str(path), "document": idx, "object": name, "where": where, "title": title, "fix": fix})

    if kind != "Namespace" and not meta.get("namespace") and kind not in {"ClusterRole", "ClusterRoleBinding", "CustomResourceDefinition", "StorageClass", "PersistentVolume", "Node", "PriorityClass"}:
        add("K8S-011", "info", "metadata.namespace", "No namespace set", "Set metadata.namespace (or apply with -n) so the object cannot land in default by accident.")
    if kind == "Service":
        t = (doc.get("spec") or {}).get("type")
        if t in {"NodePort", "LoadBalancer"}:
            add("K8S-012", "info", "spec.type", f"Service type {t} is reachable from outside the cluster", "Confirm the exposure is intended; prefer an Ingress or Gateway with TLS for HTTP services.")
        return findings
    if kind == "Secret":
        if (doc.get("data") or doc.get("stringData")):
            add("K8S-013", "medium", "data", "Secret manifest carries inline secret material", "Keep secret values out of version control: use SealedSecrets, SOPS, External Secrets or create them out of band.")
        return findings
    pod = pod_spec_of(doc)
    if pod is None:
        return findings
    if kind == "Deployment":
        spec = doc.get("spec") or {}
        if (spec.get("replicas") in (None, 1)) and not spec.get("strategy"):
            add("K8S-016", "low", "spec.replicas", "Single replica without an update strategy", "Run at least two replicas for availability, or set strategy explicitly for a stateful singleton.")
    pod_sc = pod.get("securityContext") or {}
    for flag in ("hostNetwork", "hostPID", "hostIPC"):
        if pod.get(flag) is True:
            add("K8S-008", "high", f"spec.{flag}", f"{flag}: true shares the node namespace", "Remove it unless the workload is a node agent that needs it.")
    for v in pod.get("volumes") or []:
        hp = (v or {}).get("hostPath")
        if isinstance(hp, dict):
            p = str(hp.get("path", ""))
            sev = "critical" if any(p == d or p.startswith(d + "/") and d != "/" for d in DANGEROUS_HOSTPATHS) or p == "/" else "high"
            add("K8S-008", sev, f"spec.volumes[{v.get('name')}].hostPath", f"hostPath volume mounts {p} from the node", "Use a PersistentVolumeClaim, ConfigMap or emptyDir; hostPath gives the pod access to the node filesystem.")
    if pod.get("automountServiceAccountToken") is not False and not pod.get("serviceAccountName"):
        add("K8S-010", "low", "spec.automountServiceAccountToken", "Default service account token is mounted", "Set automountServiceAccountToken: false unless the pod calls the API server; give API clients their own ServiceAccount.")
    if not (pod_sc.get("seccompProfile") or {}).get("type"):
        containers_with = [c for c in (pod.get("containers") or []) if ((c.get("securityContext") or {}).get("seccompProfile") or {}).get("type")]
        if len(containers_with) != len(pod.get("containers") or []):
            add("K8S-015", "low", "spec.securityContext.seccompProfile", "No seccompProfile", "Set securityContext.seccompProfile.type: RuntimeDefault at the pod level.")
    all_containers = [("containers", c) for c in (pod.get("containers") or [])] + [("initContainers", c) for c in (pod.get("initContainers") or [])]
    for group, c in all_containers:
        cname = c.get("name", "?")
        where = f"spec.{group}[{cname}]"
        sc = c.get("securityContext") or {}
        image = str(c.get("image", ""))
        if image:
            tail = image.split("/")[-1]
            if "@sha256:" not in image:
                if ":" not in tail:
                    add("K8S-007", "high", f"{where}.image", f"Image {image} has no tag (resolves to latest)", "Pin an immutable tag or a digest.")
                elif tail.rsplit(":", 1)[1] in {"latest", "stable", "main", "master"}:
                    add("K8S-007", "high", f"{where}.image", f"Image {image} uses a mutable tag", "Pin an immutable tag or a digest; rollbacks and reproducibility depend on it.")
        res = c.get("resources") or {}
        limits = res.get("limits") or {}
        requests = res.get("requests") or {}
        if not limits.get("memory"):
            add("K8S-001", "high", f"{where}.resources.limits.memory", "No memory limit", "Set resources.limits.memory so one container cannot evict its neighbours.")
        if not requests.get("cpu") or not requests.get("memory"):
            add("K8S-001", "high", f"{where}.resources.requests", "No cpu or memory request", "Set resources.requests so the scheduler can place the pod and the QoS class is predictable.")
        if sc.get("privileged") is True:
            add("K8S-002", "critical", f"{where}.securityContext.privileged", "Privileged container", "Remove privileged: true; grant specific capabilities if a node-level feature is needed.")
        if sc.get("runAsNonRoot") is not True and pod_sc.get("runAsNonRoot") is not True:
            if not (isinstance(sc.get("runAsUser"), int) and sc.get("runAsUser") > 0) and not (isinstance(pod_sc.get("runAsUser"), int) and pod_sc.get("runAsUser") > 0):
                add("K8S-003", "high", f"{where}.securityContext.runAsNonRoot", "Container may run as root", "Set runAsNonRoot: true (and a runAsUser in the image or spec).")
        if sc.get("allowPrivilegeEscalation") is not False:
            add("K8S-004", "medium", f"{where}.securityContext.allowPrivilegeEscalation", "allowPrivilegeEscalation not false", "Set allowPrivilegeEscalation: false.")
        if sc.get("readOnlyRootFilesystem") is not True:
            add("K8S-005", "medium", f"{where}.securityContext.readOnlyRootFilesystem", "Root filesystem is writable", "Set readOnlyRootFilesystem: true and mount emptyDir volumes where the process writes.")
        caps = sc.get("capabilities") or {}
        added = {str(x).upper() for x in (caps.get("add") or [])}
        dropped = {str(x).upper() for x in (caps.get("drop") or [])}
        if added & DANGEROUS_CAPS:
            add("K8S-006", "high", f"{where}.securityContext.capabilities.add", "Dangerous capabilities added: " + ", ".join(sorted(added & DANGEROUS_CAPS)), "Remove them; most of these give root-equivalent access to the node.")
        if "ALL" not in dropped:
            add("K8S-006", "medium", f"{where}.securityContext.capabilities.drop", "Capabilities not dropped", "Set capabilities.drop: [ALL] and add back only what is needed (for example NET_BIND_SERVICE).")
        if kind in LONG_RUNNING and group == "containers":
            if not c.get("livenessProbe"):
                add("K8S-009", "medium", f"{where}.livenessProbe", "No livenessProbe", "Add a liveness probe so a hung process is restarted.")
            if not c.get("readinessProbe"):
                add("K8S-009", "medium", f"{where}.readinessProbe", "No readinessProbe", "Add a readiness probe so traffic is not routed before the process can serve it.")
        for e in c.get("env") or []:
            if isinstance(e, dict) and SECRET_KEY_RE.search(str(e.get("name", ""))) and isinstance(e.get("value"), str) and len(e["value"]) >= 8:
                add("K8S-014", "high", f"{where}.env[{e.get('name')}]", "Secret-looking env var with a literal value", "Use valueFrom.secretKeyRef and keep the value out of the manifest.")
    return findings


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout):  # Windows pipes default to a legacy code page; read and write UTF-8
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high")
    args = ap.parse_args(argv)
    try:
        files = collect(args.paths)
    except FileNotFoundError as exc:
        print(f"error: path not found: {exc}", file=sys.stderr)
        return 2
    if not files:
        print("error: no manifest files found", file=sys.stderr)
        return 2
    findings: list[dict] = []
    parse_errors: list[str] = []
    objects = 0
    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        try:
            docs = [json.loads(text)] if f.suffix == ".json" else load_all(text)
        except (YAMLError, json.JSONDecodeError) as exc:
            parse_errors.append(f"{f}: {exc}")
            continue
        for i, doc in enumerate(docs):
            if isinstance(doc, dict) and doc.get("kind") == "List":
                docs.extend(doc.get("items") or [])
                continue
            if isinstance(doc, dict) and "kind" in doc:
                objects += 1
            findings += review_doc(f, i, doc)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda x: (order[x["severity"]], x["file"], x["object"], x["where"]))
    counts = {s: sum(1 for x in findings if x["severity"] == s) for s in SEVERITIES}
    report = {"version": VERSION, "files": [str(f) for f in files], "objects": objects, "findings": findings, "parse_errors": parse_errors, "counts": counts, "fail_on": args.fail_on}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"k8s-manifest-review {VERSION}: {objects} objects in {len(files)} file(s), {len(findings)} findings " + ", ".join(f"{s}={counts[s]}" for s in SEVERITIES if counts[s]))
        for x in findings:
            print(f"  [{x['severity']:<8}] {x['id']} {x['object']} {x['where']}: {x['title']}\n      fix: {x['fix']}")
        for e in parse_errors:
            print(f"  parse error: {e}")
    if parse_errors:
        return 2
    worst = min((order[x["severity"]] for x in findings), default=99)
    return 1 if worst <= order[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
