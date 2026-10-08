load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "testutil",
    testonly = 1,
    srcs = [
        "testutil_amd64.go",
        "testutil_arm64.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/platform/systrap/testutil",
    visibility = ["//pkg/sentry/platform/systrap:__pkg__"],
)
