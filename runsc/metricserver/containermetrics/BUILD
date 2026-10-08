load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "containermetrics",
    srcs = ["containermetrics.go"],
    importpath = "gvisor.dev/gvisor/runsc/metricserver/containermetrics",
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/prometheus",
        "//runsc/container",
        "//runsc/specutils",
    ],
)
