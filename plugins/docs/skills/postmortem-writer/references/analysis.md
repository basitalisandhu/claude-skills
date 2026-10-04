# Analysis prompts

Work through these for every incident. Several will produce "not applicable"; the rest produce the conditions and amplifiers.

## Trigger versus conditions

- What changed just before the first symptom (deploy, config, data, traffic, dependency, certificate, time)? That is the trigger.
- Why did that change cause harm instead of being rejected, limited, or noticed? Each answer is a condition. Keep asking "and why was that possible?" for each branch until the answer is a design or process property, not a person's action.
- A person's action is never the end of a branch: ask what made that action reasonable at the time (what they saw, what the tooling suggested, what the docs said).

## Detection

- How was the incident detected: alert, dashboard, customer, employee by chance?
- What is the earliest signal in the data that something was wrong, and why did nothing fire on it?
- Did the alert that fired say what was wrong and where, or only that something was?

## Diagnosis

- What did the responders look at first, and was it the right place? What information would have shortened the search?
- Which hypotheses were pursued and abandoned? What ruled them out?
- Were logs, metrics and traces correlated (request ids, deploy markers)?

## Mitigation and recovery

- What was the first mitigation attempted, and why that one? Did it work, partly, or make it worse?
- Was rollback possible, and how long did it take? What slowed it?
- Was there a runbook? Was it followed? Was it right?
- Were there safety mechanisms (limits, circuit breakers, feature flags, canaries, backpressure) that should have engaged and did not, or engaged too late?

## Amplifiers

- Retries, queues, caches, or autoscaling that turned a small failure into a large one.
- Shared dependencies that spread the failure across services.
- Communication: who knew what when; status page delay; customer-facing teams informed late.
- Fatigue and time of day; single points of knowledge.

## Near misses and luck

- What would have happened an hour later, on a weekend, with twice the traffic, or if a specific person had been unavailable?
- Which part of the recovery depended on something not guaranteed (a cached image, a laptop with the right credentials, someone remembering a command)?

## Choosing actions

For each condition and amplifier, consider, in order of preference:

1. Remove the hazard (safer default, limit, validation at the source).
2. Make the failure impossible to miss (alert on the earliest signal, with the cause in the message).
3. Make recovery fast and boring (one-command rollback, feature flag, drill).
4. Document (runbook, decision record), when the above are not possible.

Reject actions that cannot be verified as done, that depend on everyone remembering something, or that have no owner. Limit the list to what will be completed within a quarter; put the rest in the tracker as "considered, not scheduled" with the reason.
