load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "testutil",
    testonly = 1,
    srcs = [
        "sh.go",
        "testutil.go",
        "testutil_runfiles.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sync",
        "//runsc/config",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_kr_pty//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
