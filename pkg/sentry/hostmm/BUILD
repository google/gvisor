load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "hostmm",
    srcs = [
        "cgroup.go",
        "hostmm.go",
        "membarrier.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/hostmm",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/eventfd",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "hostmm_test",
    size = "small",
    srcs = ["membarrier_test.go"],
    embed = [":hostmm"],
)
