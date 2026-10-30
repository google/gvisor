load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "timing",
    srcs = ["timing.go"],
    importpath = "gvisor.dev/gvisor/pkg/timing",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/log",
    ],
)

go_test(
    name = "timing_test",
    size = "small",
    srcs = ["timing_test.go"],
    embed = [":timing"],
    deps = ["@com_github_google_go_cmp//cmp:go_default_library"],
)
