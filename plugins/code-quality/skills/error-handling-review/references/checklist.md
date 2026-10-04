# Error handling checklist

## A. At every catch or error check

| # | Question | Severity if no |
|---|---|---|
| A1 | Is the error either handled (the program can continue correctly) or re-raised with context? Catch-and-ignore counts as neither | high |
| A2 | Is the caught type as narrow as the handling? `except Exception` / `catch (e)` around code that can only fail one way hides bugs | medium |
| A3 | Is the original error preserved (`raise ... from e`, `%w`, `cause`)? | medium |
| A4 | Does the message say what was being attempted and with what (ids, names, sizes), without secrets or full payloads? | medium |
| A5 | Is it logged exactly once, at the boundary, with the stack trace? Logging at every layer produces duplicates; logging nowhere produces silence | medium |
| A6 | Does control flow after the catch make sense (no partial writes left behind, transactions rolled back, resources closed)? | high |

## B. At every outbound call (HTTP, database, queue, filesystem, subprocess)

| # | Question | Severity if no |
|---|---|---|
| B1 | Is there a timeout, both to connect and to read? | high |
| B2 | Are retries bounded (count and total time) with backoff and jitter, and only for errors that can succeed on retry (timeouts, 429, 503, connection reset), never for 4xx or validation errors? | high |
| B3 | Is the operation idempotent before it is retried (idempotency keys for payments and messages)? | high |
| B4 | Is there a circuit breaker or budget so a dead upstream does not take the caller down? | medium |
| B5 | Is cancellation propagated (context, signals, async cancellation)? | medium |

## C. At the boundary (handler, command, consumer, job)

| # | Question | Severity if no |
|---|---|---|
| C1 | Is there one handler that maps every error class to a response (status code, message) and a log line, so nothing escapes as a raw 500 or a crash without a log? | high |
| C2 | Do user-facing messages exclude stack traces, SQL, file paths, hostnames and library names? | high |
| C3 | Is a correlation or request id in the response and in the log, so a user report can be found? | medium |
| C4 | Do validation errors say which field and why? | low |
| C5 | Do queue consumers distinguish retryable failures (nack, requeue with delay) from poison messages (dead-letter after N attempts)? | high |
| C6 | Do CLI tools exit non-zero on failure and print the reason to stderr? | medium |

## D. Across the codebase

| # | Question | Severity if no |
|---|---|---|
| D1 | Is there a small hierarchy of error types (base error, invalid input, not found, conflict, unauthorised, upstream) used consistently instead of strings and generic exceptions? | medium |
| D2 | Are errors values with fields (code, details) rather than parsed messages? | medium |
| D3 | Are expected failures (not found, validation) separated from bugs, so bugs page someone and expected failures do not? | medium |
| D4 | Do tests cover the failure paths (timeout, 503, invalid input, partial failure)? | medium |
| D5 | Are unhandled errors at the top level (uncaught exception hooks, unhandled rejections, panics) logged and turned into a crash rather than a hang? | high |
