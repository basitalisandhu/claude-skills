# Forbidden phrases for narrative_lint.py

ISO/IEC 27001 control text belongs to ISO and IEC, and the SOC 2 criteria text belongs to the AICPA. Narratives drafted
with these skills name a control by its identifier (A.8.15, CC8.1) and describe its topic in the writer's own words.
They never quote the standard.

narrative_lint.py reads this file by default and refuses any line of more than 25 words that contains one of the
phrases listed below. The list ships empty on purpose: this repository does not reproduce control text, not even as
a blocklist. If your organisation holds a licensed copy of the standard, you may add distinctive phrases from it in a
local copy of this file (never in a public fork), so that text pasted from the standard is caught before a narrative
leaves your hands. The same section exists in control-map-from-exports/references/iso27001-identifiers.md and
soc2-identifiers.md; pass any of these files with `--phrases`.

## Paraphrase rule

- Identifier plus your own short topic, at most 20 words.
- No sentence copied from the standard, its guidance, or the AICPA criteria and points of focus.
- When in doubt, cite the identifier and describe what the evidence shows, not what the control says.

## Phrases

Format: one phrase per line, each line starting with `phrase:` followed by the text.

<!-- Add phrase: lines below this comment in your local copy. -->
