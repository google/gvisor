# Benchmarking seccheck

Macro-benchmarks measure the impact of `seccheck` on end-to-end container
workloads (like compiling `absl` or serving HTTP traffic). They run via the
global `make run-benchmark` wrapper.

Pre-configured JSON configurations are checked into this directory.

## Install the Instrumented Runtime

Install the customized `runsc-seccheck` docker alias by utilizing the pre-built
configuration target. This links Docker natively against
`null_bench_config.json` by default:

```shell
$ make setup-seccheck
```

If you want to benchmark against the `remote` sink or your own custom config,
you can hot-swap it immediately inline without modifying the `Makefile`:

```shell
$ make setup-seccheck SECCHECK_BENCH_CONFIG=$(pwd)/test/benchmarks/seccheck/remote_bench_config.json
```

## Run the Benchmark

Execute your chosen workload against the new instrumented runtime constraint.
The ABSL build benchmark (`BenchmarkBuildABSL` in
`//test/benchmarks/fs:bazel_test`) is the standard workload favored for testing
`execve` and general syscall overhead, as Bazel orchestrates thousands of
short-lived compiler processes.

**Tracepoint Selection Note**: The default `null_bench_config.json` and
`remote_bench_config.json` files are tuned specifically for this
`BenchmarkBuildABSL` workload and are hard-coded to trace only
`syscall/execve/enter`.

```shell
$ make run-benchmark-seccheck \
    BENCHMARKS_TARGETS="//test/benchmarks/fs:bazel_test" \
    BENCHMARKS_FILTER="BenchmarkBuildABSL"
```

> **Note:** To track allocation hotspots and garbage collection (GC) churn
> triggered by trace point structures, you can run the benchmark with profiling
> enabled: `$ make run-benchmark-seccheck ...
> BENCHMARKS_PROFILE='-pprof-dir=/tmp/profile -pprof-heap -pprof-cpu'` and
> follow up with `go tool pprof` on the resulting dumps.

## Example: Profiling the Execve Hash Cache

When `seccheck` is configured to collect the expensive `binary_sha256` payload
on `execve` events, it leverages an internal hash cache to avoid mathematically
rehashing identical binaries. You can isolate exactly how much CPU time this
cache saves by running three explicit benchmark passes:

### Pass 0: Baseline

This executes the raw uninstrumented `runsc`. Sentry engine without any
`seccheck` interception scaffolding compiled natively into the binary,
representing the pure execution limit.

```shell
make dev && \
make run-benchmark \
    BENCHMARKS_TARGETS="//test/benchmarks/fs:bazel_test" \
    BENCHMARKS_FILTER="BenchmarkBuildABSL" \
    BENCHMARKS_OPTIONS="-test.count=5" 2>&1 | tee baseline_benchmark.log
```

> **Note:** Alternatively, you can use the instrumented runtime with a zero-cost
> configuration by passing `SECCHECK_BENCH_CONFIG=null_bench_config.json` to
> `make setup-seccheck`.

### Pass 1: Cache Enabled

This requests the `binary_sha256` payload and allows the Sentry to use its
default cache capacity.

> **Note:** The default size of this internal LRU cache is `512` distinct binary
> paths per sandbox session. You can tune this capacity up or down manually by
> defining an `execve_hash_cache_capacity` property within the `options` block
> of your `.json` configuration file.

```shell
make setup-seccheck SECCHECK_BENCH_CONFIG=$(pwd)/test/benchmarks/seccheck/hash_cached_bench_config.json && \
make run-benchmark-seccheck \
    BENCHMARKS_TARGETS="//test/benchmarks/fs:bazel_test" \
    BENCHMARKS_FILTER="BenchmarkBuildABSL" \
    BENCHMARKS_OPTIONS="-test.count=5" 2>&1 | tee benchmark_result_cache.log
```

### Pass 2: Cache Disabled

This requests the exact same `binary_sha256` payload, but explicitly injects an
`options` block that sets `execve_hash_cache_capacity: 0`. It forces the Sentry
to perform a raw SHA256 digest on every single `execve`.

```shell
make setup-seccheck SECCHECK_BENCH_CONFIG=$(pwd)/test/benchmarks/seccheck/hash_nocache_bench_config.json && \
make run-benchmark-seccheck \
    BENCHMARKS_TARGETS="//test/benchmarks/fs:bazel_test" \
    BENCHMARKS_FILTER="BenchmarkBuildABSL" \
    BENCHMARKS_OPTIONS="-test.count=5" 2>&1 | tee benchmark_results_nocache.log
```

### What to expect

This example uses the ABSL benchmark. The ABSL build orchestrates thousands of
short-lived compiler processes (spawning the exact same `gcc`, `ld`, and `bash`
binaries repeatedly).

-   **Baseline:** provides IPC and compilation performance inside the generic
    Sentry sandbox unburdened by syscall interception telemetry.
-   **Cache enabled:** the Sentry only incurs the heavy disk-read and SHA256
    calculation mathematically on the very first compilation hit. On subsequent
    invocations, the Sentry detects the identical ELF binary footprint and
    serves the hash instantly.
-   **Cache disabled:** the Sentry is forced to repetitively map and recalculate
    the SHA-256 digest from scratch across all thousands of compiler runs
    uniformly, dramatically dragging down the Operations/Second throughput.

### Benchmark Results Comparison

The following table demonstrates the measured compilation throughput (in
seconds, smaller is better) between invoking raw `execve` hashing on every
syscall vs leveraging `execve_hash_cache_capacity`:

Filesystem | Page Cache | With Cache (s) | Without Cache (s) | Improvement
:--------- | :--------- | -------------: | ----------------: | --------------:
`bindfs`   | `clean`    | **459**        | **480**           | **4.4% faster**
`bindfs`   | `dirty`    | **492**        | **480**           | *(Slower)*
`tmpfs`    | `clean`    | **472**        | **487**           | **3.1% faster**
`tmpfs`    | `dirty`    | **481**        | **491**           | **2.0% faster**
`rootfs`   | `clean`    | **496**        | **490**           | *(Slower)*
`rootfs`   | `dirty`    | **481**        | **499**           | **3.6% faster**
`fusefs`   | `clean`    | **480**        | **496**           | **3.2% faster**
`fusefs`   | `dirty`    | **485**        | **490**           | **1.0% faster**

**Note:** You may observe runs where `Without Cache` execution is *faster* than
`With Cache` execution. Because each benchmark iteration executes an 8-minute
macro-compilation, background CPU contention, host OS scheduling noise, or
network variability can inject variance. While repeating loops (`-test.count=5`)
statistically filters out the largest massive spikes by discarding the extremes,
minor host-level CPU priority jitter can still bleed into the isolated true
medians.

## Example: Profiling Seccheck Memory Overheads (Redis)

`redis-benchmark` can be used to answer concerns about the memory allocation
(`allocs/op`) and garbage collection (GC) pressure that `seccheck` may inflict,
Redis is heavily dependent on `syscall` throughput (specifically thousands of
socket loops per second), making it an ideal candidate to flush out Sentry
memory leaks or GC spikes.

**Tracepoint Selection Note**: Unlike the ABSL benchmark which forks processes
(`execve`), the Redis benchmark does endless I/O over the network and executes
almost no `execve` calls. The `redis_*_bench_config.json` files are explicitly
overwritten to capture `syscall/read/enter` and `syscall/write/enter` to ensure
high-frequency trace generation during this test.

### Pass 1: Baseline (Disabled)

This runs the Redis macro-benchmark under a standard `runsc` sandbox without any
telemetry configurations initialized. We enable native profiling to collect a
baseline heap profile and execution trace:

```shell
make setup-seccheck \
    SECCHECK_BENCH_CONFIG=$(pwd)/test/benchmarks/seccheck/empty_bench_config.json \
    RUNTIME_ARGS="--debug --profile=true --profile-heap=/tmp/redis-baseline-heap.prof --trace=/tmp/redis-baseline-trace.out" && \
make run-benchmark-seccheck \
    BENCHMARKS_TARGETS="//test/benchmarks/database:redis_test" \
    BENCHMARKS_OPTIONS="-test.benchtime=2s -test.count=6" \
    BENCHMARKS_FILTER="BenchmarkRedis" 2>&1 | tee redis_baseline.log
```

**Tip for GC Tracing:** To explicitly count Garbage Collection cycles, you can
prefix any of the following `make run-benchmark-seccheck` commands with
`GODEBUG=gctrace=1`. This prints raw GC statistics (and Stop-The-World pause
timings) directly to the logs. *Note: Doing this consumes extra CPU cycles and
introduces a minor observer effect penalty on max throughput.*

```
GODEBUG=gctrace=1 make run-benchmark-seccheck ...
```

### Pass 2: Base Instrumentation (Null Sink)

This enables `seccheck` using a `null` sink configuration (to discard the
serialized events instantly, eliminating remote IPC networking lag). This tests
the absolute memory allocation cost strictly inside the Sentry when it
dynamically intercepts high-frequency network events and generates Protobuf
payload context structures.

```shell
make setup-seccheck \
    SECCHECK_BENCH_CONFIG=$(pwd)/test/benchmarks/seccheck/redis_null_bench_config.json \
    RUNTIME_ARGS="--debug --profile=true --profile-heap=/tmp/redis-null-heap.prof --trace=/tmp/redis-null-trace.out" && \
make run-benchmark-seccheck \
    BENCHMARKS_TARGETS="//test/benchmarks/database:redis_test" \
    BENCHMARKS_OPTIONS="-test.benchtime=2s -test.count=6" \
    BENCHMARKS_FILTER="BenchmarkRedis" 2>&1 | tee redis_null_sink.log
```

### Pass 3: IPC Transfer Overhead (Remote Sink)

This enables `seccheck` using a `remote` sink. To isolate the extreme cost of
the Sentry serializing and pushing bytes over the inter-process boundary (IPC),
we launch a dummy listener in the background that instantly accepts and discards
the Unix Domain Socket bytes.

```shell
# Start a dummy UDS listener that discards the IPC bytes (SOCK_SEQPACKET type)
python3 $(pwd)/test/benchmarks/seccheck/dummy_uds_server.py &
DUMMY_PID=$!

# Configure and run the benchmark sending to the socket
make setup-seccheck \
    SECCHECK_BENCH_CONFIG=$(pwd)/test/benchmarks/seccheck/redis_remote_bench_config.json \
    RUNTIME_ARGS="--profile=true --profile-heap=/tmp/redis-remote-heap.prof --trace=/tmp/redis-remote-trace.out" && \
make run-benchmark-seccheck \
    BENCHMARKS_TARGETS="//test/benchmarks/database:redis_test" \
    BENCHMARKS_OPTIONS="-test.benchtime=2s -test.count=6" \
    BENCHMARKS_FILTER="BenchmarkRedis" 2>&1 | tee redis_remote_sink.log

# Kill the dummy listener and clean up the socket lock
kill $DUMMY_PID
rm -f /tmp/seccheck.sock
```

### Analysis and Comparison

#### Comparing Application Throughput (QPS)

To compare the performance logs and see the exact QPS drop between the baseline
and the instrumentation, use the official Go `benchstat` tool:

```shell
# Install benchstat if you don't already have it
go install golang.org/x/perf/cmd/benchstat@latest

~/go/bin/benchstat baseline=redis_baseline.log null=redis_null_sink.log remote=redis_remote_sink.log
```

#### Comparing Memory Overhead (Profiles)

Instead of manually analyzing raw text logs, we use Go's built-in tooling to
subtract the baseline memory profile from the seccheck profile. This isolates
the exact code paths and memory overhead introduced exclusively by the
telemetry.

**Option 1: Terminal Text Output** For a quick look directly in your terminal,
output a ranked diff table:

```shell
# Compare Data Generation Overhead (Null Sink target)
go tool pprof -top -diff_base=/tmp/redis-baseline-heap.prof /tmp/redis-null-heap.prof

# Compare Total IPC Overhead (Remote Sink target)
go tool pprof -top -diff_base=/tmp/redis-baseline-heap.prof /tmp/redis-remote-heap.prof
```

**Option 2: Interactive Web UI** To view a visual flamegraph or the timeline
trace, start a local web server:

```shell
# View the heap flamegraph for Null Sink (Internal CPU Cost)
go tool pprof -no_browser -http=0.0.0.0:8080 -diff_base=/tmp/redis-baseline-heap.prof /tmp/redis-null-heap.prof

# View the heap flamegraph for Remote Sink (Cross-Boundary IPC Cost)
go tool pprof -no_browser -http=0.0.0.0:8080 -diff_base=/tmp/redis-baseline-heap.prof /tmp/redis-remote-heap.prof

# View the execution timeline trace for Null Sink
# (safely ignore the X11 error if it appears, trace doesn't support -no_browser)
go tool trace -http=0.0.0.0:8081 /tmp/redis-null-trace.out
```

*(Navigate to `http://<your-machine-ip-or-hostname>:8080` in your browser).*

### What to expect

-   **What it measures:** The `redis-benchmark` isolates operations throughput
    (in Queries Per Second) across workloads (e.g., `SET`, `LPUSH`) whilst
    simultaneously recording all memory allocations (`allocs/op`) and Garbage
    Collection sweep pauses natively into the `.prof` and `.out` files.
-   **What to look for:** You should compare the memory profiles (`pprof`) to
    see if the sheer act of generating the `seccheck` context objects is
    creating a high volume of garbage. Then, compare the execution traces
    (`trace`) to see if frequent GC "Stop The World" (STW) pauses are actively
    starving the Redis socket loops of CPU time.

### Interpreting the Benchmark Results

By comparing the three generated logs (Baseline vs. Null Sink vs. Remote Sink),
we can decompose the performance cost of Seccheck tracing into two distinct
architectural phases: **Data Generation** and **Data Export**.

Here is an example real-world result from `redis_test.go` tracing constant
`read` and `write` activity:

```text
                       │  baseline   │               null                │               remote               │
                       │   SET.rps   │   SET.rps    vs base              │   SET.rps    vs base               │
Redis/operation.SET-96   39.22k ± 3%   37.62k ± 3%  -4.08% (p=0.015 n=6)   28.16k ± 0%  -28.20% (p=0.002 n=6)
```

#### Data Generation Overhead (Baseline vs. Null Sink)

The Null Sink measures strictly the CPU and Memory cost of intercepting the
syscalls, gathering context data, and formatting the Protobuf trace objects
in-memory (before instantly discarding them).

**Result:** The overhead of structuring traces inside the Sentry drops
operations throughput by **~4%**. Future optimizations should aim to bring this
down to **<1%**.

#### Data Export Overhead (Baseline vs. Remote Sink)

The Remote Sink measures the total end-to-end burden of tracing, which heavily
includes writing the serialized Protobufs over a Unix Domain Socket (UDS) and
crossing the Inter-Process Communication boundary to an external daemon.

**Result:** Serializing and moving the data out of the socket drops operations
throughput by a massive **~28%**.
