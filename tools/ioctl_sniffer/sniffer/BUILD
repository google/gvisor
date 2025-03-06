load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "sniffer",
    srcs = [
        "sniffer.go",
        "sniffer_bridge.go",
    ],
    visibility = ["//tools/ioctl_sniffer:__subpackages__"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/nvgpu",
        "//pkg/log",
        "//pkg/sentry/devices/nvproxy",
        "//pkg/sentry/devices/nvproxy/nvconf",
        "//tools/ioctl_sniffer:ioctl_go_proto",
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)
