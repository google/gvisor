load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "dockerutil",
    testonly = 1,
    srcs = ["dockerutil.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//runsc/testutil",
        "@com_github_kr_pty//:go_default_library",
    ],
)
