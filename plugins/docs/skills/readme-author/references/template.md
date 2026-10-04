# README template

Keep the order. Delete sections that do not apply rather than leaving them empty.

```markdown
# <name>

<One sentence: what it does, for whom.>

<Optional: two or three lines on why it exists or how it differs from the obvious alternative. Facts only.>

## Install

<one command per supported method; the primary one first>

Requires <runtime and version, from CI>. Tested on <platforms, from CI>.

## Quick start

<the smallest command that proves it works>

<its real output>

## Usage

### <Most common task>

<Command or code, then one or two sentences on what it does.>

### <Second task>

### <Third task>

## Configuration

| Option | Default | Description |
|---|---|---|
| `<flag or env var>` | `<default>` | <what it changes> |

<Or: "See docs/configuration.md" when the table would exceed a screen.>

## How it works

<One paragraph on the mechanism, only when users need it to use the tool well (what runs where, what it reads and writes, what it never does).>

## Development

<clone, install dev dependencies, run tests, run lint>

See CONTRIBUTING.md for the ground rules.

## Security

<What the tool touches (network, files, credentials) and how to report a vulnerability: link to SECURITY.md.>

## Licence

<SPDX name>. See LICENSE.
```

## Quality checklist

- [ ] The first screen (title, sentence, install, quick start) fits without scrolling.
- [ ] Every command was run and its output pasted from the run.
- [ ] Every link resolves; every referenced file exists.
- [ ] Requirements and platforms come from CI or the manifest.
- [ ] No "simply", "just", "easy", "powerful", "blazing", "seamless".
- [ ] No feature, benchmark or integration that is not in the repository.
- [ ] Licence named and matches the LICENSE file and package metadata.
- [ ] The package or repository description equals the first sentence.
- [ ] Headings in the template order; nothing above Install except the description.
