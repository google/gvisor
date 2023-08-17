load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "clusterflag",
    srcs = ["clusterflag.go"],
    deps = [
        "//tools/gvisor_k8s_tool/cluster",
        "//tools/gvisor_k8s_tool/provider/gke",
        "//tools/gvisor_k8s_tool/provider/kubectl",
    ],
)
