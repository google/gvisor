load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "metricclient",
    testonly = 1,
    srcs = [
        "metricclient.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/sync",
        "//runsc/config",
        "//runsc/sandbox",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_prometheus_common//expfmt",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
