load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "gke",
    srcs = ["gke.go"],
    deps = [
        "//tools/gvisor_k8s_tool/cluster",
        "//tools/gvisor_k8s_tool/util",
        "@io_k8s_client_go//tools/clientcmd:go_default_library",
    ],
)
