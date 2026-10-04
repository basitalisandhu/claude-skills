# Trace formats by runtime

| Runtime | Innermost frame | Chain marker | Project frames look like | Notes |
|---|---|---|---|---|
| Python | last | `During handling of the above exception, another exception occurred` (implicit) and `The above exception was the direct cause` (`raise ... from`) | `File "/app/..."`; libraries under `site-packages` | Read bottom to top; the last line is the type and message; `ExceptionGroup` prints sub-exceptions with `+` tree markers |
| JavaScript (browser) | first | `cause` property, printed by some consoles as `Caused by` | `at fn (http://host/app.js:12:34)` or source-mapped paths | Minified traces need source maps; `TypeError: Cannot read properties of undefined (reading 'x')` names the property, not the undefined variable |
| Node.js | first | `[cause]:` printed below the stack | `at fn (/app/src/x.js:12:34)`; libraries under `node_modules`; `node:internal` is the runtime | Async frames appear after `at async`; a trace that ends in `node:internal/process/task_queues` started in a promise with no handler |
| Java / Kotlin / JVM | first | `Caused by:` (read the last `Caused by` first); `... 42 more` means frames repeated from the enclosing trace | `at com.example.App.run(App.java:42)`; frameworks are `org.springframework`, `jakarta`, `io.netty` | `NullPointerException` in modern JVMs names the null expression; `ClassNotFoundException` is a packaging problem, not code |
| Go | first (`goroutine N [running]:` then frames) | none; errors are values, so the trace is a panic or a wrapped error chain printed with `%+v` | `main.handler(...) /app/main.go:42 +0x1f` | Each frame has two lines (function, then file:line); `[recovered]` means a deferred recover re-panicked; `goroutine` dumps for all goroutines appear on fatal errors and deadlocks (`all goroutines are asleep`) |
| Rust | first after `thread 'main' panicked at src/main.rs:10:5:` | `RUST_BACKTRACE=1` prints frames; `=full` includes std | `at ./src/main.rs:10:5` | `unwrap()` on `None` or `Err` is the usual panic; the message names the `Err` value |
| .NET | first | `---> Inner exception` and `--- End of inner exception stack trace ---` | `at App.Orders.Refund(Int32 id) in /app/Orders.cs:line 42` | Async methods show `MoveNext()` and `ExceptionDispatchInfo.Throw`; ignore those frames |
| Ruby | first | `(cause)` lines when raised with cause | `/app/lib/x.rb:42:in 'method'` | `NoMethodError: undefined method 'x' for nil` names the receiver as nil |
| PHP | first (`#0`) | `Next` for chained exceptions | `#0 /app/src/x.php(42): fn()` | Fatal errors print one line without a trace unless `xdebug` or `display_errors` is on |

## Error classes and the next diagnostic

| Error class | Examples | What it means | Next step |
|---|---|---|---|
| Shape mismatch | `TypeError`, `AttributeError`, `NoMethodError`, `ClassCastException`, `Cannot read properties of undefined` | A value had a different type or shape than the code assumed | Log or inspect the value at the first project frame; check the producer (API response, parser, migration) |
| Missing data | `KeyError`, `IndexError`, `ArrayIndexOutOfBounds`, `NoSuchElement`, `nil map` | The data lacks an expected key or is shorter than assumed | Find which input lacks it; check for off-by-one and optional fields |
| Null | `NullPointerException`, `NoneType has no attribute`, `undefined is not a function`, `nil pointer dereference` | An optional value was used without a check | Trace where the value is produced; add the check or make the type non-optional |
| Environment | `ConnectionRefused`, `ECONNRESET`, `Timeout`, `ENOENT`, `Permission denied`, `UnknownHost` | The outside world was not as configured | Verify configuration, DNS, ports, credentials, file paths in the failing environment |
| Invariant | `AssertionError`, `IllegalStateException`, `panic: ...`, `unreachable` | The code reached a state it declares impossible | Find the sequence of operations that reached it; this is usually a logic bug upstream |
| Resource | `MemoryError`, `OutOfMemoryError`, `too many open files`, `StackOverflow`, `RecursionError` | Growth without bound or recursion without base case | Measure (heap dump, file handle count); look for loops that accumulate |
| Data integrity | `IntegrityError`, `UniqueViolation`, `ForeignKeyViolation`, `DeadlockDetected` | The database rejected the write | Check for duplicate requests, missing idempotency, lock ordering |
| Serialization | `JSONDecodeError`, `UnicodeDecodeError`, `SyntaxError` in parsers | Input was not in the expected format | Capture the raw input bytes at the boundary |
