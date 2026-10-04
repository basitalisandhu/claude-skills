# Good first issues

Small, self-contained tasks for this repository's own code. Each one is open as of 2026-10-04. Comment on the matching issue, or open one, before you start.

1. **`--json` for `install.py --list`.** Print the plugins, skills and install names as JSON so other tools can read them. Add a test in `tests/test_install.py`.
2. **A Windows path test for `install.py`.** Add a test that runs the install on a path with spaces and checks the manifest stores forward-slash relative paths. Add `windows-latest` to the test matrix in `.github/workflows/ci.yml`.
3. **A search box on the site index with no external dependency.** A plain HTML form that filters the skill list. It must still work, as a full list, with JavaScript off.
4. **A per-plugin Atom feed.** `site/build.py` writes one `feed.xml` today. Add `plugins/<plugin>/feed.xml` and link it from each plugin page.
5. **A "copy install command" button on skill pages.** Optional JavaScript, inline, under 1 KB. The page must read the same without it.
6. **A page size check.** Make `site/build.py --check` fail when any page is over 100 KB, and print the largest pages.
7. **A test for `scripts/sync.py --source-dir`.** Build two fake source repositories in `tmp_path` with `git init`, sync from them, and check that a second run with no change writes nothing.
8. **List the plugin-level parts on the index.** Show on the site index which plugins ship hooks, commands, agents or an MCP server, from `catalog.json`.
