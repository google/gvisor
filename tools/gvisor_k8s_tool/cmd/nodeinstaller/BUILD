load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_binary(
    name = "nodeinstaller",
    srcs = ["main.go"],
    deps = [
        "//pkg/log",
        "//tools/gvisor_k8s_tool/installer",
        "@io_k8s_client_go//kubernetes:go_default_library",
        "@io_k8s_client_go//rest:go_default_library",
    ],
)
