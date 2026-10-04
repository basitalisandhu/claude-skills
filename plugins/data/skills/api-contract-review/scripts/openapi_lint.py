#!/usr/bin/env python3
"""Lint an OpenAPI 3.x document (JSON or YAML) for the contract problems that bite clients later.

Checks (id, severity):
  OAS-000 error    not OpenAPI 3.x, missing info.title/info.version, missing or empty paths
  OAS-001 error    operation without operationId, or duplicate operationId
  OAS-002 error    operation without responses, or without any 2xx (or default) response
  OAS-003 warn     no 4xx or default error response documented
  OAS-004 error    path parameter in the template ({id}) not declared, or declared but not in the template
  OAS-005 error    parameter without schema or content; missing `in` or `name`
  OAS-006 warn     operation without summary or description; parameter without description
  OAS-007 warn     POST, PUT or PATCH without a requestBody
  OAS-008 warn     response without content (apart from 204, 304 and 1xx) or content without a schema
  OAS-009 warn     server URL uses http:// (not localhost) or contains an unresolved {variable} without a default
  OAS-010 warn     no securitySchemes, or operations without security while global security is empty
  OAS-011 info     component schema defined but never referenced; $ref to a missing component
  OAS-012 warn     tag used on an operation but not declared in the top-level tags
  OAS-013 info     path with a trailing slash, or mixed path casing styles (camelCase and snake_case) across the API
  OAS-014 warn     schema object with type object but no properties and no additionalProperties
  OAS-015 info     operation without an example (request or response)

Usage:
    openapi_lint.py SPEC [--json] [--fail-on error|warn|info]

Exit codes: 0 nothing at or above --fail-on (default: error), 1 otherwise, 2 unreadable input.
Standard library only (bundled minimal YAML reader). Read-only. No network.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _miniyaml import YAMLError, load  # noqa: E402

VERSION = "0.1.0"
LEVELS = ["error", "warn", "info"]
METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
PATH_PARAM_RE = re.compile(r"\{([^}/]+)\}")


def walk_refs(obj, out: set[str]) -> None:
    if isinstance(obj, dict):
        ref = obj.get("$ref")
        if isinstance(ref, str):
            out.add(ref)
        for v in obj.values():
            walk_refs(v, out)
    elif isinstance(obj, list):
        for v in obj:
            walk_refs(v, out)


def has_example(obj) -> bool:
    if isinstance(obj, dict):
        if "example" in obj or "examples" in obj:
            return True
        return any(has_example(v) for k, v in obj.items() if k != "$ref")
    if isinstance(obj, list):
        return any(has_example(v) for v in obj)
    return False


def lint(doc) -> list[dict]:
    findings: list[dict] = []

    def add(fid, level, where, title, fix):
        findings.append({"id": fid, "level": level, "where": where, "title": title, "fix": fix})

    if not isinstance(doc, dict):
        add("OAS-000", "error", "", "Document is not an object", "An OpenAPI document is a JSON/YAML object with openapi, info and paths.")
        return findings
    version = str(doc.get("openapi", ""))
    if not version.startswith("3."):
        add("OAS-000", "error", "openapi", f"Not an OpenAPI 3.x document (openapi: {version or 'missing'})", "Set openapi: 3.0.3 or 3.1.0; Swagger 2.0 is not covered by this linter.")
    info = doc.get("info") or {}
    if not info.get("title"):
        add("OAS-000", "error", "info.title", "Missing info.title", "Add a title.")
    if not info.get("version"):
        add("OAS-000", "error", "info.version", "Missing info.version", "Add the API version (not the OpenAPI version).")
    for i, s in enumerate(doc.get("servers") or []):
        url = str((s or {}).get("url", ""))
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            add("OAS-009", "warn", f"servers[{i}].url", f"Server over plain http: {url}", "Serve the API over https.")
        for var in PATH_PARAM_RE.findall(url):
            if "default" not in ((s.get("variables") or {}).get(var) or {}):
                add("OAS-009", "warn", f"servers[{i}].url", f"Server variable {{{var}}} has no default", "Add servers[].variables.<name>.default.")
    components = doc.get("components") or {}
    schemes = components.get("securitySchemes") or {}
    global_security = doc.get("security")
    declared_tags = {t.get("name") for t in (doc.get("tags") or []) if isinstance(t, dict)}
    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        add("OAS-000", "error", "paths", "Missing or empty paths", "Add at least one path.")
        paths = {}
    op_ids: dict[str, str] = {}
    styles = set()
    undeclared_tags: set[str] = set()
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        if path != "/" and path.endswith("/"):
            add("OAS-013", "info", f"paths.{path}", "Path has a trailing slash", "Drop it; most routers treat /a and /a/ differently.")
        for seg in PATH_PARAM_RE.sub("", path).split("/"):
            if "_" in seg:
                styles.add("snake_case")
            if re.search(r"[a-z][A-Z]", seg):
                styles.add("camelCase")
            if "-" in seg:
                styles.add("kebab-case")
        template_params = set(PATH_PARAM_RE.findall(path))
        path_level = [p for p in (item.get("parameters") or []) if isinstance(p, dict)]
        for method, op in item.items():
            if method not in METHODS or not isinstance(op, dict):
                continue
            where = f"{method.upper()} {path}"
            oid = op.get("operationId")
            if not oid:
                add("OAS-001", "error", where, "Missing operationId", "Add a unique operationId; generated clients use it as the method name.")
            elif oid in op_ids:
                add("OAS-001", "error", where, f"Duplicate operationId {oid} (also {op_ids[oid]})", "Make operationIds unique across the document.")
            else:
                op_ids[oid] = where
            if not op.get("summary") and not op.get("description"):
                add("OAS-006", "warn", where, "No summary or description", "Add a one-line summary.")
            params = path_level + [p for p in (op.get("parameters") or []) if isinstance(p, dict)]
            declared_path_params = set()
            for p in params:
                if "$ref" in p:
                    continue
                name, loc = p.get("name"), p.get("in")
                if not name or not loc:
                    add("OAS-005", "error", where, "Parameter without name or in", "Every parameter needs name and in (path, query, header, cookie).")
                    continue
                if loc == "path":
                    declared_path_params.add(name)
                    if p.get("required") is not True:
                        add("OAS-005", "error", f"{where} param {name}", "Path parameter not marked required: true", "Path parameters must be required.")
                if "schema" not in p and "content" not in p:
                    add("OAS-005", "error", f"{where} param {name}", "Parameter without schema", "Add schema (type, format) or content.")
                if not p.get("description"):
                    add("OAS-006", "warn", f"{where} param {name}", "Parameter without description", "Describe what it selects and its format.")
            for missing in sorted(template_params - declared_path_params):
                if not any("$ref" in p for p in params):
                    add("OAS-004", "error", where, f"Path parameter {{{missing}}} in the template is not declared", "Declare it with in: path, required: true and a schema.")
            for extra in sorted(declared_path_params - template_params):
                add("OAS-004", "error", where, f"Path parameter {extra} declared but not in the template", "Add {" + extra + "} to the path or change in: to query.")
            responses = op.get("responses")
            if not isinstance(responses, dict) or not responses:
                add("OAS-002", "error", where, "No responses", "Document at least the success response and one error response.")
            else:
                codes = [str(c) for c in responses]
                if not any(c.startswith("2") or c == "default" for c in codes):
                    add("OAS-002", "error", where, "No 2xx or default response", "Add the success response.")
                if not any(c.startswith(("4", "5")) or c == "default" for c in codes):
                    add("OAS-003", "warn", where, "No 4xx, 5xx or default error response", "Document validation and not-found errors with a shared error schema.")
                for code, resp in responses.items():
                    code = str(code)
                    if not isinstance(resp, dict) or "$ref" in resp:
                        continue
                    if code in {"204", "304"} or code.startswith("1"):
                        continue
                    content = resp.get("content")
                    if not content and method != "head":
                        add("OAS-008", "warn", f"{where} response {code}", "Response without content", "Add content with a media type and schema, or use 204 for an empty body.")
                    elif isinstance(content, dict):
                        for mt, media in content.items():
                            if isinstance(media, dict) and "schema" not in media:
                                add("OAS-008", "warn", f"{where} response {code} {mt}", "Content without schema", "Add a schema so clients can be generated and validated.")
            if method in {"post", "put", "patch"} and "requestBody" not in op:
                add("OAS-007", "warn", where, f"{method.upper()} without requestBody", "Add requestBody with a schema, or document why the body is empty.")
            if schemes and "security" not in op and not global_security:
                add("OAS-010", "warn", where, "Operation has no security requirement and no global security applies", "Add security: [] for public operations, or a scheme.")
            for t in op.get("tags") or []:
                if declared_tags and t not in declared_tags:
                    add("OAS-012", "warn", where, f"Tag {t} is not declared in top-level tags", "Add it to tags with a description so documentation groups it.")
                elif not declared_tags:
                    undeclared_tags.add(str(t))
            if not has_example(op):
                add("OAS-015", "info", where, "No example on the request or responses", "Add an example per media type; docs and mocks use them.")
    if len(styles) > 1:
        add("OAS-013", "info", "paths", "Mixed path naming styles: " + ", ".join(sorted(styles)), "Pick one style for path segments.")
    if undeclared_tags:
        add("OAS-012", "info", "tags", "Operations use tags but the document declares none: " + ", ".join(sorted(undeclared_tags)), "Add a top-level tags list with a description per tag.")
    if not schemes:
        add("OAS-010", "warn", "components.securitySchemes", "No securitySchemes declared", "Declare the authentication scheme (bearer, apiKey, oauth2) even for internal APIs.")
    refs: set[str] = set()
    walk_refs(doc, refs)
    local_refs = {r for r in refs if r.startswith("#/components/")}
    for section in ("schemas", "responses", "parameters", "requestBodies", "headers", "securitySchemes"):
        for name, obj in (components.get(section) or {}).items():
            ref = f"#/components/{section}/{name}"
            if section == "schemas" and ref not in local_refs:
                add("OAS-011", "info", ref, "Schema defined but never referenced", "Remove it or reference it.")
            if section == "schemas" and isinstance(obj, dict) and obj.get("type") == "object" and not obj.get("properties") and "additionalProperties" not in obj and not any(k in obj for k in ("allOf", "oneOf", "anyOf", "$ref")):
                add("OAS-014", "warn", ref, "Object schema without properties", "List the properties, or set additionalProperties explicitly for a free-form map.")
    for r in sorted(local_refs):
        parts = r[2:].split("/")
        node = doc
        for part in parts:
            node = node.get(part) if isinstance(node, dict) else None
            if node is None:
                add("OAS-011", "error", r, "$ref points to a missing component", "Fix the reference or add the component.")
                break
    order = {lv: i for i, lv in enumerate(LEVELS)}
    findings.sort(key=lambda f: (order[f["level"]], f["where"], f["id"]))
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("spec")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", choices=LEVELS, default="error")
    args = ap.parse_args(argv)
    p = Path(args.spec)
    if not p.is_file():
        print(f"error: not a file: {p}", file=sys.stderr)
        return 2
    text = p.read_text(encoding="utf-8", errors="replace")
    try:
        doc = json.loads(text) if p.suffix == ".json" or text.lstrip().startswith("{") else load(text)
    except (json.JSONDecodeError, YAMLError) as exc:
        print(f"error: cannot parse {p}: {exc}", file=sys.stderr)
        return 2
    findings = lint(doc)
    order = {lv: i for i, lv in enumerate(LEVELS)}
    counts = {lv: sum(1 for f in findings if f["level"] == lv) for lv in LEVELS}
    ops = sum(1 for item in ((doc.get("paths") or {}).values() if isinstance(doc, dict) and isinstance(doc.get("paths"), dict) else []) if isinstance(item, dict) for m in item if m in METHODS)
    report = {"version": VERSION, "file": str(p), "operations": ops, "findings": findings, "counts": counts, "fail_on": args.fail_on}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"openapi-lint {VERSION}: {p}: {ops} operations, {counts['error']} errors, {counts['warn']} warnings, {counts['info']} notes")
        for f in findings:
            print(f"  [{f['level']:<5}] {f['id']} {f['where']}: {f['title']}\n          fix: {f['fix']}")
    worst = min((order[f["level"]] for f in findings), default=99)
    return 1 if worst <= order[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
