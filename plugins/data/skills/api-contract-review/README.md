# api-contract-review

Review an OpenAPI 3.x spec (openapi.yaml or JSON) for consistency, versioning, error responses and client friendliness after a bundled script lints it: missing operationIds, undeclared path parameters, responses without schemas, http servers, missing security schemes, dangling components, naming.

Use it when asked to "review this OpenAPI spec", when designing a REST API contract, before publishing a spec, or when a client generator chokes on it.
Not for GraphQL or gRPC, implementing endpoints, version numbers (semver-advisor) or one payload's JSON Schema (json-schema-author).

Claude follows [SKILL.md](SKILL.md); it is part of the `data` plugin (`/plugin install data@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/data/skills/api-contract-review/scripts/openapi_lint.py tests/fixtures/api-contract-review/openapi.yaml
```

Inside Claude Code the skill runs `openapi_lint.py` from `${CLAUDE_PLUGIN_ROOT}/skills/api-contract-review/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/api-contract-review/` (synthetic data):

<!-- sample: plugins/data/skills/api-contract-review/scripts/openapi_lint.py tests/fixtures/api-contract-review/openapi.yaml -->
```text
openapi-lint 0.1.0: tests/fixtures/api-contract-review/openapi.yaml: 3 operations, 9 errors, 13 warnings, 8 notes
  [error] OAS-011 #/components/schemas/Missing: $ref points to a missing component
          fix: Fix the reference or add the component.
  [error] OAS-001 GET /petOwners: Duplicate operationId createPet (also POST /pet_store/{id}/)
          fix: Make operationIds unique across the document.
  [error] OAS-002 GET /petOwners: No 2xx or default response
          fix: Add the success response.
  [error] OAS-001 GET /pet_store/{id}/: Missing operationId
          fix: Add a unique operationId; generated clients use it as the method name.
  [error] OAS-004 GET /pet_store/{id}/: Path parameter {id} in the template is not declared
          fix: Declare it with in: path, required: true and a schema.
  [error] OAS-004 POST /pet_store/{id}/: Path parameter {id} in the template is not declared
          fix: Declare it with in: path, required: true and a schema.
  [error] OAS-004 POST /pet_store/{id}/: Path parameter petId declared but not in the template
          fix: Add {petId} to the path or change in: to query.
  [error] OAS-005 POST /pet_store/{id}/ param petId: Path parameter not marked required: true
          fix: Path parameters must be required.
  [error] OAS-000 info.version: Missing info.version
          fix: Add the API version (not the OpenAPI version).
  [warn ] OAS-014 #/components/schemas/Unused: Object schema without properties
          fix: List the properties, or set additionalProperties explicitly for a free-form map.
  [warn ] OAS-006 GET /petOwners: No summary or description
          fix: Add a one-line summary.
  [warn ] OAS-008 GET /petOwners response 404: Response without content
          fix: Add content with a media type and schema, or use 204 for an empty body.
  [warn ] OAS-003 GET /pet_store/{id}/: No 4xx, 5xx or default error response
          fix: Document validation and not-found errors with a shared error schema.
  [warn ] OAS-006 GET /pet_store/{id}/: No summary or description
          fix: Add a one-line summary.
  [warn ] OAS-008 GET /pet_store/{id}/ response 200: Response without content
          fix: Add content with a media type and schema, or use 204 for an empty body.
  [warn ] OAS-003 POST /pet_store/{id}/: No 4xx, 5xx or default error response
          fix: Document validation and not-found errors with a shared error schema.
  [warn ] OAS-007 POST /pet_store/{id}/: POST without requestBody
          fix: Add requestBody with a schema, or document why the body is empty.
  [warn ] OAS-006 POST /pet_store/{id}/ param petId: Parameter without description
          fix: Describe what it selects and its format.
  [warn ] OAS-008 POST /pet_store/{id}/ response 201 application/json: Content without schema
          fix: Add a schema so clients can be generated and validated.
  [warn ] OAS-010 components.securitySchemes: No securitySchemes declared
          fix: Declare the authentication scheme (bearer, apiKey, oauth2) even for internal APIs.
  [warn ] OAS-009 servers[0].url: Server over plain http: http://api.example.com/{version}
          fix: Serve the API over https.
  [warn ] OAS-009 servers[0].url: Server variable {version} has no default
          fix: Add servers[].variables.<name>.default.
  [info ] OAS-011 #/components/schemas/Ref: Schema defined but never referenced
          fix: Remove it or reference it.
  [info ] OAS-011 #/components/schemas/Unused: Schema defined but never referenced
          fix: Remove it or reference it.
  [info ] OAS-015 GET /petOwners: No example on the request or responses
          fix: Add an example per media type; docs and mocks use them.
  [info ] OAS-015 GET /pet_store/{id}/: No example on the request or responses
          fix: Add an example per media type; docs and mocks use them.
  [info ] OAS-015 POST /pet_store/{id}/: No example on the request or responses
          fix: Add an example per media type; docs and mocks use them.
  [info ] OAS-013 paths: Mixed path naming styles: camelCase, snake_case
          fix: Pick one style for path segments.
  [info ] OAS-013 paths./pet_store/{id}/: Path has a trailing slash
          fix: Drop it; most routers treat /a and /a/ differently.
  [info ] OAS-012 tags: Operations use tags but the document declares none: owners
          fix: Add a top-level tags list with a description per tag.
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
