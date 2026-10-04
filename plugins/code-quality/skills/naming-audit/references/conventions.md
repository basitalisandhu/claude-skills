# Naming rules

A rule is applied only after the local convention is known. "Consistent with the project" beats "ideal".

## Rules

| Rule | Bad | Better | Why |
|---|---|---|---|
| Say what it is, at the reader's level of detail | `d`, `tmp`, `x2` | `days_until_expiry`, `retry_delay` | A reader should not need the definition to understand a use |
| Functions are verbs or verb phrases; they say what they do, including side effects | `user()`, `data()` | `load_user()`, `fetch_prices()` | A noun-named function hides whether it computes, fetches or mutates |
| Booleans read as predicates | `flag`, `valid`, `deleted` | `is_valid`, `has_items`, `was_deleted` | `if is_valid:` reads as English |
| Collections are plural, elements singular | `user_list`, `item` for a list | `users`, `for user in users` | Plural signals iteration; `_list` leaks the type |
| Units in the name when the type does not carry them | `timeout`, `size`, `delay` | `timeout_seconds`, `size_bytes`, `delay_ms` | Every unit bug starts here |
| No needless words | `user_data`, `OrderManager`, `helper`, `utils` | `user`, `Orders` or `OrderRepository`, a specific name | `data`, `info`, `manager`, `helper` carry no information |
| Do not lie | `get_user` that inserts, `is_valid` that raises, `cache` that never evicts | `get_or_create_user`, `validate`, `memo` | A name that mismatches behaviour costs a bug per reader |
| One word per concept | `fetch`, `retrieve`, `get`, `load` used interchangeably | pick one per meaning: `get` (memory), `load` (disk), `fetch` (network) | Readers infer meaning from the verb |
| Abbreviations only when the project already uses them | `cust_nm`, `calc_tot` | `customer_name`, `calculate_total` | Each abbreviation is a small puzzle |
| Scope-proportional length | a 30-character loop index; a one-letter module global | `i` in a 3-line loop; `DEFAULT_RETRY_COUNT` at module level | Short names for short scopes, descriptive names for long ones |
| Type suffixes only when they disambiguate | `UserClass`, `nameString` | `User`, `name`; keep `UserError`, `UserRepository` | Hungarian prefixes rot; role suffixes help |
| Files and modules named after their main content | `misc.py`, `stuff.ts` | `invoice_rendering.py`, `date-parsing.ts` | Findability |
| Constants say what, not the value | `TEN = 10` | `MAX_RETRIES = 10` | The value may change; the meaning does not |
| Negatives read positively | `not_found`, `disable_cache = False` | `found`, `cache_enabled = True` | Double negatives cause mistakes |
| Public names are stable | renaming a JSON field or CLI flag casually | alias, deprecate, remove | Callers you cannot see |

## Case conventions by ecosystem (defaults when the project has none)

| Kind | Python | JavaScript / TypeScript | Go | SQL |
|---|---|---|---|---|
| Variables, functions | `snake_case` | `camelCase` | `camelCase` (exported `PascalCase`) | `snake_case` |
| Classes, types | `PascalCase` | `PascalCase` | `PascalCase` | n.a. |
| Constants | `UPPER_SNAKE` | `UPPER_SNAKE` (module) | `PascalCase` or `camelCase` | n.a. |
| Files | `snake_case.py` | `kebab-case.ts` or match the export | `snake_case.go` | `snake_case` tables |
| Booleans | `is_`, `has_`, `can_`, `should_` | same | `Is`, `Has` | `is_` |
| Timestamps | `created_at`, `expires_at` | same | `CreatedAt` | `created_at` |

## Enforcement

- Python: `ruff` rule set `N` (pep8-naming), `pylint` `invalid-name` with a regex per kind.
- JavaScript / TypeScript: `eslint` `@typescript-eslint/naming-convention` with one entry per kind.
- SQL: a migration lint (`sqlfluff` rule `references.keywords`, custom check on column suffixes).
