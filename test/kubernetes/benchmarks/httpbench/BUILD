load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//test/kubernetes:__subpackages__"],
    licenses = ["notice"],
)

go_library(
    name = "httpbench",
    testonly = 1,
    srcs = ["httpbench.go"],
    visibility = [
        "//test/kubernetes/benchmarks:__subpackages__",
    ],
    deps = [
        "//test/kubernetes",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/api/resource:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
    ],
)
