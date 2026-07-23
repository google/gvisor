load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "ebpf",
    srcs = [
        "ebpf.go",
        "types.go",
    ],
    imports = ["gvisor.dev/gvisor/pkg/abi/linux"],
    visibility = ["//visibility:public"],
    deps = ["//pkg/abi/linux"],
)
