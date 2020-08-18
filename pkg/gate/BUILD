load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "gate",
    srcs = [
        "gate.go",
    ],
    visibility = ["//visibility:public"],
)

go_test(
    name = "gate_test",
    srcs = [
        "gate_test.go",
    ],
    deps = [
        ":gate",
        "//pkg/sync",
    ],
)
