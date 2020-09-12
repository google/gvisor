load("//tools:defs.bzl", "go_library", "go_test")

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
    visibility = ["//tools/go_marshal/test:__subpackages__"],
    deps = ["//tools/go_marshal/test/external"],
)

go_test(
    name = "marshal_test",
    size = "small",
    srcs = ["marshal_test.go"],
    deps = [
        ":test",
        "//pkg/marshal",
        "//pkg/syserror",
        "//pkg/usermem",
        "//tools/go_marshal/analysis",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
