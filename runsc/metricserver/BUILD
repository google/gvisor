load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "metricserver",
    srcs = [
        "metricserver.go",
        "metricserver_http.go",
        "metricserver_lifecycle.go",
        "metricserver_metrics.go",
        "metricserver_profile.go",
    ],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/log",
        "//pkg/prometheus",
        "//pkg/sentry/control",
        "//pkg/state",
        "//pkg/sync",
        "//runsc/config",
        "//runsc/container",
        "//runsc/metricserver/containermetrics",
        "//runsc/sandbox",
        "@org_golang_google_api//option:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
    ],
)

go_test(
    name = "metricserver_test",
    srcs = ["metricserver_test.go"],
    library = ":metricserver",
    deps = ["@com_github_google_go_cmp//cmp:go_default_library"],
)
