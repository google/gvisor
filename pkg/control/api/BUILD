load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "api",
    srcs = [
        "cgroups.go",
        "fs.go",
        "logging.go",
        "metrics.go",
        "pprof.go",
        "proc.go",
        "state.go",
        "usage.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/control/api",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/metric:metric_go_proto",
        "//pkg/prometheus",
        "//pkg/sentry/checkpoint",
        "//pkg/sentry/kernel/auth",
        "//pkg/sync",
        "//pkg/urpc",
    ],
)

go_test(
    name = "api_test",
    size = "small",
    srcs = ["proc_test.go"],
    embed = [":api"],
)
