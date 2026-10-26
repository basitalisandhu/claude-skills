# AWS spend guardrails

Generates AWS Budgets, a Cost Anomaly Detection monitor and a sandbox SCP that denies expensive services from a short spec, and reviews an exported Cost Explorer report for spikes against it.

Claude loads the skill from [SKILL.md](SKILL.md), which holds the workflow, the collection commands and the `## Limits` section; this page is the short version for people reading the repository. The script uses the standard library only and makes no network calls. Exit codes follow the pack: 0 clean, 1 findings to review, 2 bad input or usage (see the [plugin README](../../README.md#exit-codes)).

## Sample

Real output for the review of the committed daily Cost Explorer export (exit 1: high anomalies), run from the repository root:

````text
$ python3 plugins/aws-security/skills/aws-spend-guardrails/scripts/spend_guardrails.py review --cost-explorer tests/fixtures/spend/cost-explorer-daily.json --budget tests/fixtures/spend/budget.yaml
2026-09-10 to 2026-09-30 (21 days, USD), 2 estimated day(s)
by service:
        372.57  Amazon Elastic Compute Cloud - Compute
         83.50  Amazon SageMaker
         25.77  Amazon Simple Storage Service
          6.44  AWS Lambda
by account:
        320.27  123456789012
        168.01  111122223333
month 2026-09: 488.28 over 21 day(s), 88.8% of limit
high    SPEND-ANOMALY      Amazon Elastic Compute Cloud - Compute / 123456789012 on 2026-09-27: 86.40 vs prior 7-day median 10.08 (8.57x)
high    SPEND-ANOMALY      Amazon SageMaker / 111122223333 on 2026-09-29: 42.00 vs prior 7-day median 0.00 (new spend)
high    SPEND-ANOMALY      Amazon SageMaker / 111122223333 on 2026-09-30: 41.50 vs prior 7-day median 0.00 (new spend)
medium  SPEND-ANOMALY      total on 2026-09-27: 91.95 vs prior 7-day median 15.66 (5.87x)
medium  SPEND-ANOMALY      total on 2026-09-29: 57.65 vs prior 7-day median 15.75 (3.66x)
medium  SPEND-ANOMALY      total on 2026-09-30: 57.19 vs prior 7-day median 15.75 (3.63x)
medium  SPEND-THRESHOLD    2026-09: 88.8% of the limit, past the 80% alert threshold
````
