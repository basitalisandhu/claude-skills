# cron-doctor

Make cron jobs run when they should: a bundled script validates every crontab line, explains each schedule in plain words with its next runs, and flags missing output redirection, unescaped percent signs, PATH assumptions, day-of-month plus day-of-week confusion, DST-sensitive hours, overlaps and duplicates; then the entries are fixed with locking and logging.

Use it when a cron job did not run, ran twice or at the wrong time, to check or "review my crontab", or to write a new cron schedule.
Not for Kubernetes CronJobs beyond the schedule field, or for systemd timers.

Claude follows [SKILL.md](SKILL.md); it is part of the `devops` plugin (`/plugin install devops@claude-dev-skills`).

## Run the script

From a clone of the repository (Python 3.11 or newer, standard library only):

```bash
python3 plugins/devops/skills/cron-doctor/scripts/cron_doctor.py tests/fixtures/cron-doctor/crontab --now 2026-10-26T09:00
```

Inside Claude Code the skill runs `cron_doctor.py` from `${CLAUDE_PLUGIN_ROOT}/skills/cron-doctor/scripts/`; `--help` lists every option.

## Sample

Real output of the command above on the committed fixture in `tests/fixtures/cron-doctor/` (synthetic data):

<!-- sample: --lines=30 plugins/devops/skills/cron-doctor/scripts/cron_doctor.py tests/fixtures/cron-doctor/crontab --now 2026-10-26T09:00 -->
```text
cron-doctor 0.1.0: 9 jobs, 2 errors, 7 warnings, 1 notes
  line   4 [ok ] 30 2 * * *       at 02:30 every day
            /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1
            next: 2026-10-27T02:30, 2026-10-28T02:30, 2026-10-29T02:30
  line   5 [ok ] */5 * * * *      every 5 minutes every day
            /usr/local/bin/poll.sh
            next: 2026-10-26T09:05, 2026-10-26T09:10, 2026-10-26T09:15
  line   6 [ok ] 0 9 1 * 1        at 09:00 on day-of-month 1 OR on mon
            /usr/local/bin/report.sh > /dev/null 2>&1
            next: 2026-11-01T09:00, 2026-11-02T09:00, 2026-11-09T09:00
  line   7 [ok ] 0 9 * * *        at 09:00 every day
            /usr/local/bin/a.sh >/dev/null 2>&1
            next: 2026-10-27T09:00, 2026-10-28T09:00, 2026-10-29T09:00
  line   8 [ok ] 0 9 * * *        at 09:00 every day
            /usr/local/bin/b.sh >/dev/null 2>&1
            next: 2026-10-27T09:00, 2026-10-28T09:00, 2026-10-29T09:00
  line   9 [ok ] * * * * *        every minute every day
            +%Y > /tmp/x
            next: 2026-10-26T09:01, 2026-10-26T09:02, 2026-10-26T09:03
  line  10 [ok ] @daily           at 00:00 every day
            /usr/local/bin/rotate.sh >/dev/null 2>&1
            next: 2026-10-27T00:00, 2026-10-28T00:00, 2026-10-29T00:00
  line  11 [ok ] @daily           at 00:00 every day
            /usr/local/bin/rotate.sh >/dev/null 2>&1
            next: 2026-10-27T00:00, 2026-10-28T00:00, 2026-10-29T00:00
  line  12 [BAD] 61 * * * *
            /bin/true
  [error] CRON-004 line 9: Unescaped % in command
          fix: Escape it as \% or move the command into a script; cron converts % to a newline.
  [error] CRON-001 line 12: Invalid schedule: minute: '61' outside 0-59
...
```

## Limits

See the `## Limits` section of [SKILL.md](SKILL.md).
