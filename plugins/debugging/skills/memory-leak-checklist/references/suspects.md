# Usual suspects and their fixes

| Suspect | How it looks in the heap | Fix |
|---|---|---|
| Unbounded cache or memo (`dict` as cache, `functools.lru_cache(maxsize=None)`, `Map` in a module, in-memory session store) | One dict or map whose entry count grows with distinct inputs | Bound it: `lru_cache(maxsize=...)`, `cachetools.TTLCache`, `lru-cache` in Node, an eviction policy; or move it to Redis |
| Listeners and callbacks never removed (event emitters, signal handlers, observers, `addEventListener`, DOM nodes) | Closures or handler objects growing; `MaxListenersExceededWarning` in Node | Remove on cleanup (`off`, `removeListener`, `AbortSignal`), use weak references, scope the emitter to the request |
| Closures capturing large objects (a handler that closes over a request or a big buffer and is stored somewhere long-lived) | Function objects retaining large arrays or responses | Capture only what is needed; copy the small value out before creating the closure |
| Module-level or global collections that only grow (`_registry.append`, `history`, `seen`) | A list or set with one owner at module scope | Make it per-request, bound it, or use a counter instead of a collection |
| Per-request logging handlers, metrics registries, tracers | Handler or registry objects grow with request count | Configure once at startup; never add handlers inside request code |
| Connection, thread or process pools that grow | Sockets, threads, file descriptors increasing; `too many open files` | Fixed pool size; return connections with context managers; set `max_overflow` |
| Large buffers kept after use (`bytes` of a whole file kept on an object, `BytesIO` never closed, stream chunks accumulated) | Few objects, huge size | Stream and discard; `del` references after processing; avoid `read()` of whole files |
| Circular references with finalizers (`__del__` in Python 2 era patterns, resurrecting objects) | Objects in `gc.garbage`; growth even after `gc.collect()` | Remove `__del__`, use `weakref.finalize` or context managers |
| Third-party clients that keep history or caches (HTTP client with response cache, ORM identity map, test fixtures that accumulate) | Growth inside a library namespace | Read the client's docs for `expire`, `clear`, `max_size`; create short-lived sessions; `session.expunge_all()` for SQLAlchemy long-lived sessions |
| Metrics with unbounded label values (user id, URL with ids, request id as a label) | Time series or counter objects grow with distinct labels | Label with bounded categories; put ids in logs, not metrics |
| Goroutine, thread or task leaks (blocked forever on a channel, a lock, a never-resolving promise) | Goroutine or thread count grows; each holds its stack and references | Add timeouts and cancellation; make every goroutine have an exit path; `errgroup` with context |
| Native memory (Buffers, image libraries, GPU, compression contexts) | RSS grows while the managed heap is flat; `external` or `arrayBuffers` grows in Node | Free native resources explicitly (`close`, `dispose`, `free`); check library docs for a `release` call |
| Fragmentation (glibc malloc with many threads, long-lived small allocations) | RSS high and flat-ish, heap much smaller, returns after restart but grows slowly | `MALLOC_ARENA_MAX=2`, jemalloc, or recycle workers periodically (a mitigation, not a fix) |
