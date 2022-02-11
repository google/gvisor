load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "specutils",
    srcs = [
        "cri.go",
        "fs.go",
        "namespace.go",
        "specutils.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bits",
        "//pkg/log",
        "//pkg/sentry/kernel/auth",
        "//runsc/config",
        "//runsc/flag",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_mohae_deepcopy//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_syndtr_gocapability//capability:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "specutils_test",
    size = "small",
    srcs = ["specutils_test.go"],
    library = ":specutils",
    deps = ["@com_github_opencontainers_runtime_spec//specs-go:go_default_library"],
)
