# Writing review comments

- One finding per comment. State the problem, the evidence, and the suggested fix. "This loop never terminates when `items` is empty (line 42: `while i <= len(items)`); use `<`."
- Say the severity explicitly: blocker, major, minor, nit. The author should never have to guess whether a comment blocks the merge.
- Ask questions only when you do not know the answer. "Is this intentional?" is a finding in disguise; write what you think is wrong and let the author correct you.
- Prefer a code suggestion over prose when the fix is short.
- Praise specific things that are good (a clear test, a well-named function); it tells the author what to keep doing.
- Do not comment on formatting the project's formatter handles; if the project has no formatter, suggest adding one as a separate change.
- Keep the summary comment short: verdict, the top finding, the count of the rest.
