# Reproduction report: <title> (<issue link>)

## One-line reproduction

```
<command or test invocation that fails every time>
```

Exit code / failure: `<...>`

## Expected versus actual

| | |
|---|---|
| Expected | |
| Actual | |
| First seen | <version or date> |
| Frequency before pinning | <e.g. 3 in 10 runs> |
| Frequency after pinning | 10 in 10 |

## Environment pins

| Variable | Value | Needed? |
|---|---|---|
| OS | | no (reproduces on Linux and macOS) |
| Runtime version | | yes (only 3.12, not 3.11) |
| Dependency versions | | |
| Configuration / flags | | |
| Time / time zone | frozen at ... | |
| Random seed | | |
| Concurrency | single worker | |
| Data | fixtures/<file> (redacted, <n> lines) | yes |

## Minimisation log

| Removed | Still fails? | Kept removed? |
|---|---|---|
| step 3 (open settings page) | yes | yes |
| field `customer.address` from fixture | yes | yes |
| field `order.discount` from fixture | no | no (involved) |

## Ruled out

- <variable>: <evidence>

## Narrowed to

- Location: `<file:line>` or `<commit from git bisect>`
- Hypothesis (unverified): <one sentence>

## Regression test

`<path>::<test name>`, fails before the fix, must pass after.
