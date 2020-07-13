load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "harness",
    testonly = 1,
    srcs = [
        "harness.go",
        "machine.go",
        "util.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)
