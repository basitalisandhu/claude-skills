# dockerfile-hardening

Harden a Dockerfile before the image ships: a bundled script flags running as root, unpinned base images or the latest tag, secrets in ENV or ARG, remote scripts piped to a shell, uncleaned apt layers, world-writable files and no HEALTHCHECK, and the file is rewritten as a smaller, pinned, non-root multi-stage build.

Use it when asked to "review my Dockerfile", to check an image is safe to publish, or to harden, slim down or write a Dockerfile for a Python or Node app.
Not for Kubernetes Deployments or manifests (k8s-manifest-review) or docker-compose networking.

Claude follows [SKILL.md](SKILL.md); it is part of the `devops` plugin (`/plugin install devops@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/devops/skills/dockerfile-hardening/scripts/dockerfile_lint.py tests/fixtures/dockerfile-hardening/Dockerfile
```

Inside Claude Code the skill runs `dockerfile_lint.py` from `${CLAUDE_PLUGIN_ROOT}/skills/dockerfile-hardening/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/dockerfile-hardening/` (synthetic data):

<!-- sample: --lines=30 plugins/devops/skills/dockerfile-hardening/scripts/dockerfile_lint.py tests/fixtures/dockerfile-hardening/Dockerfile -->
```text
dockerfile-hardening 0.1.0: 18 findings in 1 file(s) critical=1, high=5, medium=7, low=5
  [critical] DF-004 tests/fixtures/dockerfile-hardening/Dockerfile:3 ENV API_KEY holds a secret-looking literal
      ENV API_KEY=set**************
      fix: Never bake secrets into images; pass them at run time (env, mounted file) or use RUN --mount=type=secret for build-time secrets.
  [high    ] DF-001 tests/fixtures/dockerfile-hardening/Dockerfile:1 FROM uses the mutable tag :latest
      python:latest
      fix: Pin a specific version tag or a digest so rebuilds are reproducible.
  [high    ] DF-002 tests/fixtures/dockerfile-hardening/Dockerfile:1 Final stage never switches to a non-root USER
      no USER instruction after the last FROM
      fix: Create a user (RUN adduser --system app) and add USER app before CMD/ENTRYPOINT.
  [high    ] DF-005 tests/fixtures/dockerfile-hardening/Dockerfile:6 Remote script piped into a shell
      curl -sSL https://example.com/install.sh | bash
      fix: Download to a file, verify a checksum or signature, then run it.
  [high    ] DF-003 tests/fixtures/dockerfile-hardening/Dockerfile:9 ADD downloads from a URL without checksum verification
      https://example.com/tool.tgz /tmp/
      fix: Use RUN curl -fsSL ... && echo '<sha256> file' | sha256sum -c, or COPY a vendored file.
  [high    ] DF-014 tests/fixtures/dockerfile-hardening/Dockerfile:11 Credential or VCS files copied into the image
      .env /app/.env
      fix: Exclude them with .dockerignore and copy only what the runtime needs.
  [medium  ] DF-006 tests/fixtures/dockerfile-hardening/Dockerfile:5 apt-get install without --no-install-recommends
      apt-get update && apt-get install -y curl && apt-get upgrade -y
      fix: Add --no-install-recommends to keep the layer small.
  [medium  ] DF-006 tests/fixtures/dockerfile-hardening/Dockerfile:5 apt lists not removed in the same layer
      apt-get update && apt-get install -y curl && apt-get upgrade -y
      fix: End the RUN with && rm -rf /var/lib/apt/lists/*.
  [medium  ] DF-017 tests/fixtures/dockerfile-hardening/Dockerfile:5 apt-get upgrade in the image build
      apt-get update && apt-get install -y curl && apt-get upgrade -y
      fix: Rebuild from a newer base image instead; upgrading inside the build makes the result depend on the day it ran.
  [medium  ] DF-008 tests/fixtures/dockerfile-hardening/Dockerfile:7 World-writable permissions
      pip install flask && chmod -R 777 /app
...
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
