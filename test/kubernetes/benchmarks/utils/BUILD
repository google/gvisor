load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "utils",
    testonly = True,
    srcs = ["utils.go"],
    importpath = "gvisor.dev/gvisor/test/kubernetes/benchmarks/utils",
)
