load("//tools:defs.bzl", "go_library")

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
    importpath = "gvisor.dev/gvisor/pkg/ebpf",
    imports = ["gvisor.dev/gvisor/pkg/abi/linux"],
    visibility = ["//visibility:public"],
    deps = ["//pkg/abi/linux"],
)
