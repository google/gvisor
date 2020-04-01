load("//tools:defs.bzl", "go_binary", "go_library", "go_test")

licenses(["notice"])

package_group(
    name = "gomarshal_test",
    packages = [
        "//tools/go_marshal/test/...",
    ],
)

go_test(
    name = "benchmark_test",
    srcs = ["benchmark_test.go"],
    deps = [
        ":test",
        "//pkg/binary",
        "//pkg/usermem",
        "//tools/go_marshal/analysis",
    ],
)

go_library(
    name = "test",
    testonly = 1,
    srcs = ["test.go"],
    marshal = True,
    deps = ["//tools/go_marshal/test/external"],
)

go_binary(
    name = "escape",
    testonly = 1,
    srcs = ["escape.go"],
    gc_goopts = ["-m"],
    deps = [
        ":test",
        "//pkg/usermem",
        "//tools/go_marshal/marshal",
    ],
)

go_test(
    name = "marshal_test",
    size = "small",
    srcs = ["marshal_test.go"],
    deps = [
        ":test",
        "//pkg/syserror",
        "//pkg/usermem",
        "//tools/go_marshal/analysis",
        "//tools/go_marshal/marshal",
        "@com_github_google_go-cmp//cmp:go_default_library",
    ],
)
