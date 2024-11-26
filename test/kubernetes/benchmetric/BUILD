load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "benchmetric",
    srcs = [
        "benchmark_printer.go",
        "benchmetric.go",
        "timing.go",
    ],
    deps = [
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
    ],
)
