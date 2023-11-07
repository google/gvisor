load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "metricclient",
    testonly = 1,
    srcs = [
        "metricclient.go",
    ],
    data = [
        "//runsc/cmd/metricserver:metricserver_bin",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/cleanup",
        "//pkg/prometheus",
        "//pkg/sync",
        "//pkg/test/testutil",
        "//runsc/config",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_prometheus_common//expfmt",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
