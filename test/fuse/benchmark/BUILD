load("//tools:defs.bzl", "cc_binary", "gbenchmark", "gtest")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
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
    name = "open_benchmark",
    testonly = 1,
    srcs = [
        "open_benchmark.cc",
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
    name = "read_benchmark",
    testonly = 1,
    srcs = [
        "read_benchmark.cc",
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
    name = "symlink_benchmark",
    testonly = 1,
    srcs = [
        "symlink_benchmark.cc",
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
    name = "mkdir_benchmark",
    testonly = 1,
    srcs = [
        "mkdir_benchmark.cc",
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
