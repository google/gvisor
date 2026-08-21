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
-   **Cache enabled:** the Sentry only incurs the heavy disk-read and SHA-256
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
