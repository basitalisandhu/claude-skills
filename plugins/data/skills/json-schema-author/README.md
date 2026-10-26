# json-schema-author

Write a JSON Schema (draft 2020-12) for an API payload, config file, webhook or event: a bundled script infers a draft from sample documents (types, required fields, nullability, formats, enums, bounds), then it is tightened by hand with constraints, descriptions, examples and additionalProperties.

Use it when asked to "write a JSON Schema", to create a schema from examples or sample payloads, or to document a payload so others can validate it.
Not for whole OpenAPI specs (api-contract-review) and not for XML or protobuf.

Claude follows [SKILL.md](SKILL.md); it is part of the `data` plugin (`/plugin install data@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/data/skills/json-schema-author/scripts/json_schema_infer.py tests/fixtures/json-schema-author/users.json --title User
```

Inside Claude Code the skill runs `json_schema_infer.py` from `${CLAUDE_PLUGIN_ROOT}/skills/json-schema-author/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/json-schema-author/` (synthetic data):

<!-- sample: --lines=40 plugins/data/skills/json-schema-author/scripts/json_schema_infer.py tests/fixtures/json-schema-author/users.json --title User -->
```text
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "User",
  "type": "object",
  "properties": {
    "created": {
      "type": "string",
      "format": "date-time",
      "examples": [
        "2024-01-01T00:00:00Z",
        "2024-01-02T00:00:00Z"
      ]
    },
    "email": {
      "type": "string",
      "format": "email",
      "examples": [
        "a@x.io",
        "b@x.io"
      ]
    },
    "id": {
      "type": "integer",
      "minimum": 1,
      "maximum": 5,
      "examples": [
        1,
        2
      ]
    },
    "meta": {
      "type": "object",
      "properties": {
        "extra": {
          "type": "boolean",
          "examples": [
            true
          ]
        },
        "k": {
...
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
