load("//test/runner:defs.bzl", "syscall_test")
load("//tools:defs.bzl", "more_shards")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

syscall_test(
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:clock_getres_benchmark",
)

syscall_test(
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:clock_gettime_benchmark",
)

syscall_test(
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:death_benchmark",
)

syscall_test(
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:epoll_benchmark",
)

syscall_test(
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:poll_benchmark",
)

syscall_test(
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:select_benchmark",
)

syscall_test(
    size = "large",
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:fork_benchmark",
)

syscall_test(
    size = "large",
    timeout = "long",
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:futex_benchmark",
)

syscall_test(
    size = "large",
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    shard_count = more_shards,
    tags = ["nogotsan"],
    test = "//test/perf/linux:getdents_benchmark",
)

syscall_test(
    size = "large",
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:getpid_benchmark",
)

syscall_test(
    size = "large",
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    tags = ["nogotsan"],
    test = "//test/perf/linux:gettid_benchmark",
)

syscall_test(
    size = "large",
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:mapping_benchmark",
)

syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:open_benchmark",
)

syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:dup_benchmark",
)

syscall_test(
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:pipe_benchmark",
)

syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:randread_benchmark",
)

syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:read_benchmark",
)

syscall_test(
    size = "large",
    debug = False,
    test = "//test/perf/linux:save_benchmark",
)

syscall_test(
    size = "large",
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:sched_yield_benchmark",
)

syscall_test(
    size = "large",
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:send_recv_benchmark",
)

syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:seqwrite_benchmark",
)

syscall_test(
    size = "large",
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:signal_benchmark",
)

syscall_test(
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:sleep_benchmark",
)

syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:stat_benchmark",
)

syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    tags = ["nogotsan"],
    test = "//test/perf/linux:unlink_benchmark",
)

syscall_test(
    size = "large",
    add_overlay = True,
    debug = False,
    # Takes too long to run with S/R.
    save = False,
    test = "//test/perf/linux:write_benchmark",
)
