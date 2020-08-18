load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "criutil",
    testonly = 1,
    srcs = ["criutil.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)
