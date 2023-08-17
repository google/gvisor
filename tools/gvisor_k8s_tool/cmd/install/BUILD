load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "install",
    srcs = ["install.go"],
    deps = [
        "//pkg/log",
        "//runsc/cmd/util",
        "//runsc/flag",
        "//tools/gvisor_k8s_tool/cluster",
        "//tools/gvisor_k8s_tool/provider/clusterflag",
        "//tools/gvisor_k8s_tool/spec",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
