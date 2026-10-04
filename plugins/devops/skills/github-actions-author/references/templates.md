# Workflow templates

Replace `<sha>` with the current commit SHA of the action (`gh api repos/actions/checkout/git/ref/tags/v4.2.2 --jq .object.sha` resolves a tag; annotated tags need one more hop to the commit). Keep the version in the comment so Dependabot can update both.

## CI (test matrix)

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    runs-on: ${{ matrix.os }}
    timeout-minutes: 15
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest]
        python: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@<sha> # v4.2.2
        with:
          persist-credentials: false
      - uses: actions/setup-python@<sha> # v5.3.0
        with:
          python-version: ${{ matrix.python }}
          cache: pip
      - run: python -m pip install -r requirements-dev.txt
      - run: python -m pytest -q
```

## Release on tag (OIDC publish, no long-lived token)

```yaml
name: release

on:
  push:
    tags: ["v*"]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@<sha> # v4.2.2
        with:
          persist-credentials: false
      - uses: actions/setup-python@<sha> # v5.3.0
        with:
          python-version: "3.12"
      - run: python -m pip install build && python -m build
      - uses: actions/upload-artifact@<sha> # v4.4.3
        with:
          name: dist
          path: dist/

  publish:
    needs: build
    runs-on: ubuntu-latest
    timeout-minutes: 10
    environment: release
    permissions:
      id-token: write    # trusted publishing
      contents: write    # create the GitHub release
    steps:
      - uses: actions/download-artifact@<sha> # v4.1.8
        with:
          name: dist
          path: dist/
      - uses: pypa/gh-action-pypi-publish@<sha> # v1.12.2
      - uses: softprops/action-gh-release@<sha> # v2.1.0
        with:
          files: dist/*
          generate_release_notes: true
```

## Safe pull-request comment (no fork code with a write token)

Run the untrusted part on `pull_request` with read permissions and upload a result; comment from a `workflow_run` job that never checks out fork code:

```yaml
name: pr-comment
on:
  workflow_run:
    workflows: [ci]
    types: [completed]
permissions:
  contents: read
jobs:
  comment:
    if: github.event.workflow_run.event == 'pull_request'
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      pull-requests: write
      actions: read
    steps:
      - uses: actions/download-artifact@<sha> # v4.1.8
        with:
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
          name: report
      - uses: actions/github-script@<sha> # v7.0.1
        with:
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('report.md', 'utf8').slice(0, 60000);
            const pr = (await github.rest.search.issuesAndPullRequests({ q: `sha:${context.payload.workflow_run.head_sha} is:pr` })).data.items[0];
            if (pr) await github.rest.issues.createComment({ ...context.repo, issue_number: pr.number, body });
```

## Expression injection: the safe form

```yaml
      - name: Use the PR title
        env:
          TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "Title: $TITLE"
```

Never `run: echo "${{ github.event.pull_request.title }}"`: the expression is substituted into the script before the shell sees it, so a title containing `$(curl ...)` runs.

## Dependabot for action pins

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```
