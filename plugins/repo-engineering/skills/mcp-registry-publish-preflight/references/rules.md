# Rules checked by registry_preflight.py

Each rule comes from the official MCP Registry's own documents or validator code, all read at commit `e47b29e` of [modelcontextprotocol/registry](https://github.com/modelcontextprotocol/registry). Nothing here is a guess about undocumented behaviour; where the registry's behaviour depends on something the script cannot see (DNS, PyPI, the image registry), the rule is marked "not checked" instead.

Sources (the `source` field in the JSON report uses the short names in brackets):

- [schema] [server.schema.json, draft](https://github.com/modelcontextprotocol/registry/blob/e47b29ec6091a4b05969d9f755a024529ee2b5b3/docs/reference/server-json/draft/server.schema.json)
- [reqs] [official-registry-requirements.md](https://github.com/modelcontextprotocol/registry/blob/e47b29ec6091a4b05969d9f755a024529ee2b5b3/docs/reference/server-json/official-registry-requirements.md)
- [pkg] [package-types.mdx](https://github.com/modelcontextprotocol/registry/blob/e47b29ec6091a4b05969d9f755a024529ee2b5b3/docs/modelcontextprotocol-io/package-types.mdx)
- [auth] [authentication.mdx](https://github.com/modelcontextprotocol/registry/blob/e47b29ec6091a4b05969d9f755a024529ee2b5b3/docs/modelcontextprotocol-io/authentication.mdx)
- [ver] [versioning.mdx](https://github.com/modelcontextprotocol/registry/blob/e47b29ec6091a4b05969d9f755a024529ee2b5b3/docs/modelcontextprotocol-io/versioning.mdx)
- [validators] [internal/validators](https://github.com/modelcontextprotocol/registry/tree/e47b29ec6091a4b05969d9f755a024529ee2b5b3/internal/validators) (`validators.go`, `utils.go`, `registries/*.go`), for rules the docs show only by example
- [auth-code] [internal/api/handlers/v0/auth/common.go](https://github.com/modelcontextprotocol/registry/blob/e47b29ec6091a4b05969d9f755a024529ee2b5b3/internal/api/handlers/v0/auth/common.go), how a proof record is parsed
- [issues] registry issues [#1707](https://github.com/modelcontextprotocol/registry/issues/1707), [#1694](https://github.com/modelcontextprotocol/registry/issues/1694), [#1715](https://github.com/modelcontextprotocol/registry/issues/1715), [#1682](https://github.com/modelcontextprotocol/registry/issues/1682) and [#1733](https://github.com/modelcontextprotocol/registry/issues/1733), for warnings about what breaks after publishing

## server.json

| Rule | Severity | Fires when | Source |
|---|---|---|---|
| `required-field` | error | `name`, `description` or `version` is missing; a package lacks `registryType`, `identifier` or `transport`; a repository lacks `url` or `source` | schema |
| `schema-type` | error | a field has the wrong JSON type (for example `packages` is not a list) | schema |
| `name-length` | error | the name is shorter than 3 or longer than 200 characters | schema |
| `name-format` | error | the name is not one `namespace/name` pair of letters, digits, `.` and `-` (`_` also allowed after the slash), each part starting and ending with a letter or digit | schema, validators |
| `description-length` | error | the description is empty or over 100 characters | schema |
| `title-length` | error | the title is empty or over 100 characters | schema |
| `version-latest` | error | the server or package version is `latest` | schema (package), validators (server) |
| `version-range` | error | a version looks like a range: `^`, `~`, `>=`, `<=`, `>`, `<` or `=` before a version, `1 - 2`, `1.2 \|\| 1.3`, or `x`, `X` or `*` in a dotted version | ver, validators |
| `version-length` | error | a version is over 255 characters, or a package version is empty | schema |
| `website-url-https` | error | `websiteUrl` is not an absolute https URL | validators |
| `icon-https` | error | an icon `src` is not an https URL | schema |
| `meta-dropped` | warn | `_meta` has a key other than `io.modelcontextprotocol.registry/publisher-provided`; the registry drops it silently | reqs |
| `meta-too-large` | error | the publisher-provided block is over 4096 bytes as compact JSON | reqs |
| `transport-type` | error | a package transport is not `stdio`, `streamable-http` or `sse`, or a remote is not `streamable-http` or `sse` | schema, validators |
| `transport-url` | error | an http transport has no `url`, or the url does not start with `http://`, `https://` or a `{variable}` | schema |
| `remote-url-https` | error | a remote url is not https | validators |
| `remote-url-localhost` | error | a remote url points at localhost | validators |
| `server-package-version` | warn | there is one package and its version differs from the server version (a `-N` suffix on the server version is allowed) | ver |

## Packages

| Rule | Severity | Fires when | Source |
|---|---|---|---|
| `registry-type` | error | `registryType` is not npm, pypi, nuget, cargo, oci or mcpb | reqs |
| `registry-base-url` | error | `registryBaseUrl` is not the one allowed URL for npm, pypi, nuget or cargo | reqs |
| `package-version-missing` | error | an npm, pypi, nuget or cargo package has no version (the registry looks up that exact version) | validators |
| `sha256-format` | error | `fileSha256` is not 64 lowercase hex characters | schema |
| `sha256-not-allowed` | error | an npm, pypi, nuget or cargo package sets `fileSha256` | validators |
| `oci-host` | error | the image registry host is not docker.io, ghcr.io, quay.io, `*.pkg.dev`, `*.azurecr.io` or mcr.microsoft.com (a bare image name counts as docker.io) | reqs, pkg |
| `oci-no-tag` | warn | the OCI identifier has no tag or digest | pkg |
| `oci-field` | error | an OCI package sets `registryBaseUrl`, `version` or `fileSha256` | validators |
| `mcpb-url` | error | the MCPB identifier is not an https URL | validators |
| `mcpb-host` | error | the MCPB file is not on github.com or gitlab.com | reqs |
| `mcpb-no-mcp` | error | the MCPB URL does not contain "mcp" (any case) | pkg |
| `mcpb-sha256` | error | an MCPB package has no `fileSha256` | pkg |

## Ownership in local package files

| Rule | Severity | Fires when | Source |
|---|---|---|---|
| `npm-mcpname-missing`, `npm-mcpname-mismatch` | error | package.json has no `mcpName`, or it is not exactly the server name | pkg |
| `npm-name-differs` | warn | package.json `name` is not the package identifier, so the file read may not be the package published | pkg |
| `marker-missing` | error | the README the package registry shows has no `mcp-name: <server name>` | pkg |
| `marker-glued` | error | the marker is followed by a character that can continue a name (for example a full stop) instead of a newline, whitespace, `<` or `-->`; the end of the file is a boundary | pkg, validators |
| `marker-case` | error | the marker is there with different letter case; the match is exact | validators, #1707 |
| `marker-other-name` | error | the README has a marker for a different name | pkg |
| `marker-in-wrong-readme` | error | pyproject `readme` names a file without the marker while README.md has it; PyPI shows the named file | pkg |
| `readme-missing` | error | the README named by pyproject, Cargo.toml, `PackageReadmeFile` or `--readme` does not exist | pkg |
| `readme-not-description` | warn | `--readme` is not the file pyproject.toml names | pkg |
| `pyproject-no-readme` | warn | pyproject.toml names no readme | pkg |
| `cargo-marker-hidden` | error | a cargo package's only marker is inside an HTML comment, which crates.io strips | pkg |
| `oci-label-missing`, `oci-label-mismatch` | error | the Dockerfile has no `LABEL io.modelcontextprotocol.server.name`, or its value is not the server name | pkg |
| `version-mismatch` | warn | the package version in server.json differs from package.json, pyproject.toml, Cargo.toml or the .csproj | ver, #1707 |

## Repository and namespace

| Rule | Severity | Fires when | Source |
|---|---|---|---|
| `repository-missing` | warn | there is no `repository` | #1715 |
| `repository-not-https` | warn | the repository url is not https | #1715 |
| `repository-source` | error | `source` is not github or gitlab | validators |
| `repository-url` | error | the url is not a github.com/owner/repo or gitlab.com/group/project URL for its source | validators |
| `repository-subfolder` | error | `subfolder` is not a clean relative path | schema, validators |
| `repository-owner-differs` | warn | an `io.github.<owner>/` name's repository is under another GitHub owner, the pattern seen after a rename | #1682, #1733 |
| `github-owner` | error | with `--github-owner`, the `io.github.<owner>` namespace is another login | auth |
| `github-owner-case` | warn | the namespace and the login differ only in letter case | auth |
| `namespace-domain` | error | with `--domain example.com`, the name is not under `com.example/` or `com.example.*/` | auth |

## Proof record (`--proof-record`)

| Rule | Severity | Fires when | Source |
|---|---|---|---|
| `proof-missing` | error | no `v=MCPv1` record in the input | auth |
| `proof-format` | error | the record is not `v=MCPv1; k=...; p=<base64>`, or `p=` holds characters outside base64 (such as a redaction placeholder), or looks like hex | auth-code, #1694 |
| `proof-algorithm` | error | `k=` is not `ed25519` or `ecdsap384` | auth |
| `proof-base64` | error | `p=` does not decode as standard base64 | auth-code |
| `proof-key-size` | error | an Ed25519 key is not 32 bytes, or a P-384 key is not 49 bytes in compressed form starting 0x02 or 0x03 | auth-code |
| `proof-key-point` | error | the P-384 key is not a point on the curve | auth-code |
| `proof-selector` | error | a zone line puts the record on `_mcp-auth.` or `_mcp-registry.` instead of the apex | auth |
| `proof-wrong-name` | error | with `--domain`, a zone line puts the record on another name | auth |
| `proof-several` | warn | more than one MCPv1 TXT record; a stale one is tried first | auth |
| `proof-too-large` | error | an HTTP proof body is over 4096 bytes | auth |
| `proof-html` | error | an HTTP proof body is an HTML page | auth |
| `proof-key-mismatch` | error | with `--expected-record`, no published record holds the expected algorithm and key | auth |

## Not checked

The script reports these as `info` (not checked) or leaves them out:

- whether the listed package version exists, installs, or has the README the local file shows (it reads local files only);
- the OCI annotation on the pushed image (it reads the Dockerfile `LABEL`, which sets it only if the image is built from that file);
- whether the private key matches the published key, and whether the registry's resolver or fetcher can reach the record (#1679, #1691);
- the MCPB file's hash (clients check it; the registry does not);
- uniqueness of remote URLs across the registry, which blocks republishing under a renamed namespace (#1682, #1733).
