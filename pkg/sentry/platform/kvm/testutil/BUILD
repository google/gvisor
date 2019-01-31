load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "testutil",
    testonly = 1,
    srcs = [
        "testutil.go",
        "testutil_amd64.go",
        "testutil_amd64.s",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/platform/kvm/testutil",
    visibility = ["//pkg/sentry/platform/kvm:__pkg__"],
)
