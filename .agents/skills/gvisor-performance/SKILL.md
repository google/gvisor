---
name: gvisor-performance
description: >
  Use when modifying gVisor in ways with potential performance implications;
  as a kernel, gVisor's performance matters almost as much as its security.
  Load imperatively when editing this performance-sensitive code:

    * Syscall hot path: `pkg/sentry/kernel` (`task_run.go`, `task_syscall.go`),
      `pkg/sentry/syscalls/linux`, and app-memory copy layers
      (`pkg/usermem`, `pkg/safemem`, `pkg/safecopy`, `pkg/marshal`).
    * Platform: `pkg/sentry/platform`, `pkg/ring0`.
    * Sandbox startup: `runsc/boot`, `runsc/container`, `runsc/sandbox`.
    * Serialization and checkpoint/restore: `pkg/state`, `pkg/sentry/state`.
    * Netstack: `pkg/tcpip`.
    * File I/O: `pkg/sentry/vfs`, `pkg/sentry/fsimpl`.
    * Memory management: `pkg/sentry/mm`, `pkg/sentry/pgalloc`.
    * Gofer IPC: `pkg/lisafs`, `runsc/fsgofer`.
    * Go `init()` functions, which run on every binary startup.

  Also load for any change with potential performance impact,
  even outside these paths.
---

## gVisor performance sensitivity

As a kernel, gVisor performance matters almost as much as security. As such, any
change that may impact performance is required to come with benchmark
measurements to measure its benefit and to avoid regressions, and must be
careful to avoid introducing performance regressions.

In particular, consider these tips when making changes in this area:

-   **Heap allocations**: Avoid heap allocations where possible, and annotate
    functions that must not allocate with `// +checkescape` so that the
    `checkescape` analyzer enforces this. In netstack, use the pooled
    reference-counted buffers in `pkg/buffer` instead of allocating and copying
    packet data.
-   **Gofer round-trips**: Each gofer RPC is a round trip to another process.
    Avoid adding RPCs to frequent file system operations; use the Sentry's
    cached file system state, or combined RPCs such as `WalkStat`.
-   **Pre-sized data structures**: When you need to use a heap-allocated
    dynamically-sized data structure such as a slice or a map, pre-allocate the
    expected capacity it will need. When no perfect proxy exists but an upper
    bound exists that isn't likely to be pathologically high, use that. When
    there is truly no way to know but that tracking historical patterns could be
    effective, do so. Do not assume Go's default sizing is the correct option.
    When possible, reuse already-allocated slices rather than allocating new
    ones within the same context.
-   **Never use `init()` functions**: `init` functions are almost never a good
    idea. They add silent startup cost to every binary invocation, even when
    unneeded. Instead, add a package-level `Init` function that actual package
    users have to call by the time it is clear it will be necessary, or
    initialize the package on first-use if doing so is cheap and doesn't have
    synchronization issues. If neither of these options is adequate, create an
    `Init` function and manually call it in `main` in all the binaries that will
    for sure use it.
    -   Similarly, also avoid allocating large data structures at the package
        level. Prefer a `sync.Once` that allocates it on first access, unless
        doing so comes with performance/synchronization overhead due to frequent
        access.
    -   Never, ever put system calls in `init` functions.
-   **Saved state**: Checkpoint latency and byte size grow the more kernel state
    is saved. Don't save state that can be rebuilt cheaply on restore; tag it
    `state:"nosave"` instead and rebuild it in `afterLoad`.
-   **Go compiler annotations**: You may use `go:nosplit` where appropriate.
    Functions that are short enough should aim to fit under Go's inlining budget
    if they are performance-sensitive and if doing so comes at no more than a
    small readability cost.

## Benchmarking methodology

For performance-impacting changes, or changes that may *potentially* impact
performance, benchmark figures are required in the PR description.

Select the subset of benchmarks in `//test/benchmarks` and
`//test/kubernetes/benchmarks` that cover the aspects of performance that may be
impacted by the change. If not already covered, also come up with new benchmarks
that demonstrate the effect the change at hand has more clearly than the
existing benchmarks do. For example, if benchmarking Gofer startup performance,
run `//test/benchmarks/base:startup_test` and
`//test/kubernetes/benchmarks:startup_test`, as well as some one-off Gofer-only
benchmarks you may design on your own.

NOTE: You **must** select at least one already-existing benchmark.
Performance-impacting changes that only come with change-specific benchmarks may
hide broader performance implications. Thus, you must select at least one broad
benchmark as well, even if the benchmark data shows no difference.

In general, selecting broad benchmarks should be done on a category basis; do
not cherrypick benchmarks. For example, if you are modifying networking code,
then you should include **all** networking benchmarks (`iperf`, `nginx`,
`redis`, etc.) and run them at **all** relevant variants (e.g. all concurrency
levels of `nginx`). If the resulting benchmark dump is too long, you may
summarize it, but do not elide it completely, as this may be perceived as an
attempt to cherrypick benchmarks.

Benchmark data must be presented as the raw output of
[Go's `benchstat` tool](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat).
This output contains the following critical pieces of information:

-   Which benchmarks were run
-   The median reading before vs after the change
-   The standard deviation of the readings (both before and after the change)
-   The percentage change between the "before" vs "after" readings
-   How many times they were run (both before and after the change)
-   The statistical significance of the results (the `p` value, resulting from
    the Mann-Whitney U-test)

As a rule of thumb, you should run benchmarks until `n≥24` on each side or
`p<0.01`, whichever happens first. Signs to push `n` further include a standard
deviation larger than 5% on microbenchmarks. Seeing `~` (indicating no
statistically-significant change) is normal and expected for benchmark metrics
where we expect no improvement nor regressions, and should therefore be included
as well for completeness. If possible, benchmark on a relatively quiet machine
to avoid benchmark noise.

You may create throwaway VMs to the extent permitted by your environment,
although note that virtualization comes with its own overhead which can distort
results and, in the case of gVisor's KVM platform, do not reflect real-world
bare-metal performance.

If none of the existing benchmarks cover the aspect of performance your change
impacts, you should add a benchmark that does.

After providing the `benchstat` table, the PR description should also explain
any surprising/non-obvious result.

## Help gVisor performance not regress

### Add new benchmarks

If a performance change improves an area of gVisor that isn't already
well-captured by the existing set of benchmarks, and that you had to write a
one-off benchmark to show the effect of a performance change, then chances are
that this means gVisor needs a new benchmark added to its permanent set in order
to ensure this aspect of gVisor performance does not regress into the future. If
this is the case, you should submit a separate PR **before** the performance
change that adds this benchmark to the permanent set. Permanent benchmarks
should be broad and generally-useful, not overly-specific to one particular
case.

For example, a benchmark measuring number of allocations in a specific tiny
codepath is **not** appropriate, but a benchmark measuring number of allocations
and GC load in gVisor while a specific workload runs in the sandbox is.

### Add `+checkescape` annotations

If your change reduces the number of allocations inside a certain codepath to
zero, then you should add the `+checkescape` annotation to ensure this does not
regress.
