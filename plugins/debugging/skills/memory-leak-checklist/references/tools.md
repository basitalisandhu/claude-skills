# Measuring the heap by runtime

Always force a garbage collection before each measurement, and measure after a fixed amount of work so two snapshots can be compared.

## Python

```python
import gc, tracemalloc
tracemalloc.start(25)              # keep 25 frames per allocation
gc.collect(); s1 = tracemalloc.take_snapshot()
# ... do 10,000 units of work ...
gc.collect(); s2 = tracemalloc.take_snapshot()
for stat in s2.compare_to(s1, "lineno")[:15]:
    print(stat)                    # size diff and count diff per allocation site
```

- Live object counts: `objgraph.show_most_common_types(limit=20)` and `objgraph.show_growth()` between two points; retaining path: `objgraph.show_backrefs(obj, max_depth=5, filename="refs.png")` or `gc.get_referrers(obj)`.
- Running process without code change: `py-spy dump -p <pid>` shows what threads hold; `memray run --live` or `memray run -o out.bin` then `memray flamegraph` for allocation sites.
- Common false leak: `sys.getsizeof` on containers ignores contents; use tracemalloc totals.

## Node.js

- Heap snapshots: start with `node --inspect`, open Chrome DevTools, Memory tab, take a snapshot, do the work, take another, choose "Comparison"; sort by "Size delta"; the "Retainers" pane shows the path to a root. From code: `v8.writeHeapSnapshot()` then load the files in DevTools.
- Quick numbers: `process.memoryUsage()` (`heapUsed`, `rss`, `external`, `arrayBuffers`); `global.gc()` is available with `node --expose-gc`.
- Allocation sampling: `node --heap-prof` writes a `.heapprofile` to load in DevTools.
- `external` and `arrayBuffers` growing while `heapUsed` is flat points at Buffers or native addons.

## Go

- `import _ "net/http/pprof"` then `go tool pprof -sample_index=inuse_space http://localhost:6060/debug/pprof/heap`; in the pprof prompt `top`, `list <func>`, `peek <func>` (callers); `-diff_base` compares two heap profiles taken before and after the work.
- `runtime.ReadMemStats` for `HeapInuse`, `HeapObjects`; `GODEBUG=gctrace=1` prints each GC cycle (the live heap after each cycle is the trough).
- Goroutine leaks show as growing goroutine counts (`/debug/pprof/goroutine?debug=1`); each goroutine holds its stack and everything it references.

## Java / JVM

- Class histogram: `jcmd <pid> GC.class_histogram | head -30` twice, diff the instance counts.
- Heap dump: `jcmd <pid> GC.heap_dump /tmp/heap.hprof` (or `-XX:+HeapDumpOnOutOfMemoryError`), open in Eclipse MAT or VisualVM, use "Leak Suspects" and "Path to GC Roots" excluding weak references.
- GC logs: `-Xlog:gc*` and look at the heap size after each full GC.

## .NET

- `dotnet-counters monitor --process-id <pid>` for GC heap size per generation; `dotnet-gcdump collect -p <pid>` twice and compare in Visual Studio or PerfView; `dotnet-dump analyze` with `dumpheap -stat` and `gcroot <address>` for the retaining path.

## Containers

- `cat /sys/fs/cgroup/memory.current` (cgroup v2) or `memory.usage_in_bytes` (v1) inside the container; `memory.stat` splits anon (heap) from file (page cache, which is reclaimable and not a leak).
- `kubectl top pod` reports working set, which includes page cache; a pod "leaking" file-backed memory from reading large files is not leaking.
