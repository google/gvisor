load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "criutil",
    testonly = 1,
    srcs = ["criutil.go"],
    nogo = False,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)
