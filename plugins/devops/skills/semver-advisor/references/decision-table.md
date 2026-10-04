# What counts as breaking, by artefact

A change is breaking when an existing, reasonable use stops working or changes meaning without the user changing anything. Additive changes with unchanged defaults are minor. Fixes that restore documented behaviour are patch.

## Library API (functions, classes, types)

| Change | Class | Notes |
|---|---|---|
| Remove or rename a public symbol | breaking | Deprecate first with a warning for one minor |
| Change a parameter type, return type, or exception type | breaking | Widening an input type is minor; narrowing is breaking |
| Add a required parameter | breaking | Add it with a default instead (minor) |
| Add an optional parameter with a default | minor | Keep positional order; append |
| Reorder positional parameters | breaking | |
| Change a default value | breaking | Even if "better" |
| Raise a new exception type from an existing call | breaking for callers that catch specific types | Subclass the existing type to make it additive |
| Make validation stricter (reject inputs previously accepted) | breaking | Unless the old acceptance was a documented bug |
| Make validation looser | minor | |
| Change behaviour of an existing input | breaking | |
| Change thread-safety, ordering guarantees, or performance class (O(n) to O(n^2)) | breaking in practice | Document and major |
| Add a method to an interface others implement | breaking (for implementers) | Default methods make it minor |
| Change a class to final, or remove a base class | breaking | |
| Drop support for a runtime version | breaking | Some ecosystems treat it as minor; say which rule the project follows |

## CLI

| Change | Class |
|---|---|
| Remove or rename a command or flag | breaking |
| Change the meaning of a flag or a positional argument | breaking |
| Change the default output format, column order, or exit codes | breaking (scripts parse them) |
| Add a flag, command, or output field in a machine-readable format (JSON) | minor |
| Add a column to human-readable output | minor, note it |
| Change human-readable wording | patch |

## HTTP or RPC API

| Change | Class |
|---|---|
| Remove an endpoint, field, enum value, or status code | breaking |
| Rename a field; change a field type; make an optional field required | breaking |
| Add a required request field or header | breaking |
| Add an optional request field, a response field, an endpoint, an enum value (if clients tolerate unknown values) | minor |
| Change a status code for an existing condition (404 to 410) | breaking |
| Change pagination, sorting or filtering defaults | breaking |
| Tighten rate limits or auth requirements | breaking |
| Change an error body shape | breaking |

Alternatives to a major: version in the path (`/v2/`) or a header, or add a new endpoint and deprecate the old with a `Sunset` header and a date.

## Configuration files and environment variables

| Change | Class |
|---|---|
| Remove or rename a key | breaking (accept both for one release) |
| Change a default | breaking |
| Change a value's type or format (seconds to milliseconds) | breaking |
| Add a key with a default | minor |

## Database schema (for consumers who read the database directly or run migrations)

| Change | Class |
|---|---|
| Drop or rename a table or column; change a column type; add NOT NULL without default | breaking; use expand, migrate, contract across releases |
| Add a nullable column, a table, an index | minor |
| Change constraints that reject existing writes | breaking |

## Container images and packages

| Change | Class |
|---|---|
| Change the entrypoint, default command, working directory, exposed port, or user | breaking |
| Change the base OS family (Debian to Alpine) | breaking (shell, libc differ) |
| Remove a tool from the image | breaking for anyone who execs it |
| Update packages, add tools | minor or patch |

## Below 1.0

Semver says anything may change. In practice: treat 0.x minor bumps as "may break", patch as safe, and write the breaking changes in the notes exactly as a 1.x major would. Move to 1.0 when the public surface is stable enough to promise.

## Pre-releases

`1.4.0-rc.1 < 1.4.0`. Use `alpha`, `beta`, `rc` with a number; never publish two builds with the same pre-release tag. Build metadata (`+20260310`) is ignored for ordering.
