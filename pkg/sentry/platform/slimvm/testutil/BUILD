load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# buildifier: disable=platform-specific-binaries
go_library(
    name = "testutil",
    testonly = 1,
    srcs = [
        "testutil.go",
        "testutil_amd64.go",
        "testutil_amd64.s",
    ],
    # TODO: b/529809802 - Enable nogo.
    nogo = False,
    target_compatible_with = [
        "@platforms//cpu:x86_64",
    ],
    visibility = ["//pkg/sentry/platform/slimvm:__pkg__"],
    deps = ["//pkg/sentry/arch"],
)
