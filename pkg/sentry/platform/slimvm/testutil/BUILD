load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "testutil",
    testonly = 1,
    srcs = [
        "testutil.go",
        "testutil_amd64.go",
        "testutil_amd64.s",
    ],
    visibility = ["//pkg/sentry/platform/slimvm:__pkg__"],
    deps = ["//pkg/sentry/arch"],
)
