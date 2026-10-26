# csv-profiler

Profile a CSV or TSV file with a bundled script (column types, nulls, distinct counts, ranges, candidate keys, ragged and duplicate rows, mixed types, whitespace) and turn it into import decisions: column types for a table, cleaning steps and validation rules.

Use it when asked to "summarise this CSV file", what is in a data export before loading it, or when an import of a CSV or TSV fails on a row.
Not for spreadsheets with formulas (export to CSV first) and not for files too large to read (use --sample).

Claude follows [SKILL.md](SKILL.md); it is part of the `data` plugin (`/plugin install data@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/data/skills/csv-profiler/scripts/csv_profiler.py tests/fixtures/csv-profiler/customers.csv
```

Inside Claude Code the skill runs `csv_profiler.py` from `${CLAUDE_PLUGIN_ROOT}/skills/csv-profiler/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/csv-profiler/` (synthetic data):

<!-- sample: --lines=30 plugins/data/skills/csv-profiler/scripts/csv_profiler.py tests/fixtures/csv-profiler/customers.csv -->
```text
csv-profiler 0.1.0: tests/fixtures/csv-profiler/customers.csv: 7 rows x 6 columns, delimiter ',', header=yes
dialect: quotechar='"', line_terminator=LF, bom=False
column                   type       nulls distinct  range / stats
id                       integer        0        6  min=1.0 max=6.0 mean=3.5714 median=4.0
name                     string         0        6  len 2-3; top: 'Dee' x2, 'Ann' x1, 'Bob' x1
amount                   number         1        5  min=-3.0 max=1000.0 mean=170.5833 median=7.0
active                   boolean        0        3  len 3-5; top: 'true' x5, 'false' x1, 'yes' x1
joined                   string         0        6  len 10-10; top: 'not a date' x2, '2024-01-02' x1, '2024-02-03' x1
note                     string         3        3  len 1-5; top: 'x' x2, 'hello' x1, 'note' x1
warnings:
  - 1 rows have a field count different from the header (first at line 8)
  - 1 duplicate rows
  - column name has 1 values with leading or trailing whitespace
  - column joined mixes types: date, string
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
