load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "testutil",
    testonly = 1,
    srcs = [
        "sh.go",
        "testutil.go",
        "testutil_runfiles.go",
        "tree.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/test/testutil",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/rand",
        "//pkg/sync",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_creack_pty//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "testutil_test",
    size = "small",
    srcs = ["testutil_test.go"],
    embed = [":testutil"],
)
