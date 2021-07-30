load("//tools:defs.bzl", "cc_binary", "gbenchmark", "gtest")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

cc_binary(
    name = "getpid_benchmark",
    testonly = 1,
    srcs = [
        "getpid_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:test_main",
    ],
)

cc_binary(
    name = "send_recv_benchmark",
    testonly = 1,
    srcs = [
        "send_recv_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:file_descriptor",
        "//test/util:logging",
        "//test/util:posix_error",
        "//test/util:socket_util",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "@com_google_absl//absl/synchronization",
    ],
)

cc_binary(
    name = "gettid_benchmark",
    testonly = 1,
    srcs = [
        "gettid_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:test_main",
    ],
)

cc_binary(
    name = "sched_yield_benchmark",
    testonly = 1,
    srcs = [
        "sched_yield_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "clock_getres_benchmark",
    testonly = 1,
    srcs = [
        "clock_getres_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:test_main",
    ],
)

cc_binary(
    name = "clock_gettime_benchmark",
    testonly = 1,
    srcs = [
        "clock_gettime_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:test_main",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "open_benchmark",
    testonly = 1,
    srcs = [
        "open_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:fs_util",
        "//test/util:logging",
        "//test/util:temp_path",
        "//test/util:test_main",
    ],
)

cc_binary(
    name = "dup_benchmark",
    testonly = 1,
    srcs = [
        "dup_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:fs_util",
        "//test/util:logging",
        "//test/util:temp_path",
        "//test/util:test_main",
    ],
)

cc_binary(
    name = "read_benchmark",
    testonly = 1,
    srcs = [
        "read_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:fs_util",
        "//test/util:logging",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "randread_benchmark",
    testonly = 1,
    srcs = [
        "randread_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:file_descriptor",
        "//test/util:logging",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "@com_google_absl//absl/random",
    ],
)

cc_binary(
    name = "write_benchmark",
    testonly = 1,
    srcs = [
        "write_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:logging",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "seqwrite_benchmark",
    testonly = 1,
    srcs = [
        "seqwrite_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:logging",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "@com_google_absl//absl/random",
    ],
)

cc_binary(
    name = "pipe_benchmark",
    testonly = 1,
    srcs = [
        "pipe_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:logging",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
    ],
)

cc_binary(
    name = "fork_benchmark",
    testonly = 1,
    srcs = [
        "fork_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:cleanup",
        "//test/util:file_descriptor",
        "//test/util:logging",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "@com_google_absl//absl/synchronization",
    ],
)

cc_binary(
    name = "futex_benchmark",
    testonly = 1,
    srcs = [
        "futex_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:logging",
        "//test/util:test_main",
        "//test/util:thread_util",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "epoll_benchmark",
    testonly = 1,
    srcs = [
        "epoll_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:epoll_util",
        "//test/util:file_descriptor",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:thread_util",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "death_benchmark",
    testonly = 1,
    srcs = [
        "death_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:logging",
        "//test/util:test_main",
    ],
)

cc_binary(
    name = "mapping_benchmark",
    testonly = 1,
    srcs = [
        "mapping_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:logging",
        "//test/util:memory_util",
        "//test/util:posix_error",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "signal_benchmark",
    testonly = 1,
    srcs = [
        "signal_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:logging",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "getdents_benchmark",
    testonly = 1,
    srcs = [
        "getdents_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:file_descriptor",
        "//test/util:fs_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "sleep_benchmark",
    testonly = 1,
    srcs = [
        "sleep_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:logging",
        "//test/util:test_main",
    ],
)

cc_binary(
    name = "stat_benchmark",
    testonly = 1,
    srcs = [
        "stat_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:fs_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "@com_google_absl//absl/strings",
    ],
)

cc_binary(
    name = "unlink_benchmark",
    testonly = 1,
    srcs = [
        "unlink_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:fs_util",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
    ],
)

cc_binary(
    name = "open_read_close_benchmark",
    testonly = 1,
    srcs = [
        "open_read_close_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:fs_util",
        "//test/util:logging",
        "//test/util:temp_path",
        "//test/util:test_main",
    ],
)

cc_binary(
    name = "verity_open_benchmark",
    testonly = 1,
    srcs = [
        "verity_open_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:capability_util",
        "//test/util:fs_util",
        "//test/util:logging",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:verity_util",
    ],
)

cc_binary(
    name = "verity_read_benchmark",
    testonly = 1,
    srcs = [
        "verity_read_benchmark.cc",
    ],
    deps = [
        gbenchmark,
        gtest,
        "//test/util:capability_util",
        "//test/util:fs_util",
        "//test/util:logging",
        "//test/util:temp_path",
        "//test/util:test_main",
        "//test/util:test_util",
        "//test/util:verity_util",
    ],
)
