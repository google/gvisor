load("//tools:defs.bzl", "cc_binary", "go_binary", "proto_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

proto_library(
    name = "ioctl",
    srcs = ["ioctl.proto"],
    visibility = ["//tools/ioctl_sniffer:__subpackages__"],
)

cc_binary(
    name = "ioctl_hook",
    srcs = [
        "ioctl_hook.cc",
        "ioctl_hook.h",
        "sniffer_bridge.cc",
        "sniffer_bridge.h",
    ],
    linkshared = True,
    deps = [
        ":ioctl_cc_proto",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_protobuf//src/google/protobuf/io",
    ],
)

go_binary(
    name = "run_sniffer",
    srcs = ["run_sniffer.go"],
    static = True,
    deps = [
        "//pkg/log",
        "//tools/ioctl_sniffer/sniffer",
    ],
)
