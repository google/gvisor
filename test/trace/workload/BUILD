load("//tools:defs.bzl", "cc_binary")

package(licenses = ["notice"])

cc_binary(
    name = "workload",
    testonly = 1,
    srcs = [
        "workload.cc",
    ],
    visibility = ["//test/trace:__pkg__"],
    deps = [
        "//test/util:file_descriptor",
        "//test/util:multiprocess_util",
        "//test/util:posix_error",
        "//test/util:test_util",
        "@com_google_absl//absl/cleanup",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ],
)
