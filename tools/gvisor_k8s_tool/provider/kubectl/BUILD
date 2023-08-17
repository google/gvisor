load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "kubectl",
    srcs = ["kubectl.go"],
    deps = [
        "//pkg/log",
        "//tools/gvisor_k8s_tool/cluster",
        "@io_k8s_client_go//tools/clientcmd:go_default_library",
    ],
)
