load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//test/kubernetes:__subpackages__"],
    licenses = ["notice"],
)

go_library(
    name = "profiling",
    testonly = 1,
    srcs = ["profiling.go"],
    visibility = [
        "//test/kubernetes:__subpackages__",
    ],
    deps = [
        "//pkg/atomicbitops",
        "//runsc/flag",
        "//test/kubernetes",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "//test/metricsviz",
        "@com_github_google_pprof//profile:go_default_library",
        "@io_k8s_api//apps/v1:go_default_library",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_time//rate:go_default_library",
    ],
)
