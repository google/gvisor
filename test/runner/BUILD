load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "runner",
    testonly = 1,
    srcs = ["runner.go"],
    data = [
        "//runsc",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/test/testutil",
        "//runsc/specutils",
        "//test/runner/gtest",
        "//test/uds",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
