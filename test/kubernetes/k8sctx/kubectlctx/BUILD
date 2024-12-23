load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "kubectlctx",
    srcs = ["kubectlctx.go"],
    nogo = False,
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//runsc/flag",
        "//test/kubernetes:test_range_config_go_proto",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "//tools/gvisor_k8s_tool/provider/kubectl",
        "@io_k8s_client_go//kubernetes:go_default_library",
        "@io_k8s_client_go//tools/clientcmd:go_default_library",
        "@org_golang_google_protobuf//encoding/prototext:go_default_library",
        "@org_golang_x_sync//errgroup:go_default_library",
    ],
)
