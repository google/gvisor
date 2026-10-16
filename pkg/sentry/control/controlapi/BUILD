load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "controlapi",
    srcs = [
        "cgroups.go",
        "controlapi.go",
        "fs.go",
        "logging.go",
        "metrics.go",
        "pprof.go",
        "proc.go",
        "state.go",
        "usage.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/log",
        "//pkg/metric:metric_go_proto",
        "//pkg/prometheus",
        "//pkg/sentry/fscheckpoint",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/usage",
        "//pkg/sync",
        "//pkg/urpc",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "controlapi_test",
    size = "small",
    srcs = ["proc_test.go"],
    embed = [":controlapi"],
)
