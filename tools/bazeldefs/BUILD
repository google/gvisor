load("//tools:defs.bzl", "bzl_library", "go_proto_library")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

bzl_library(
    name = "platforms_bzl",
    srcs = ["platforms.bzl"],
    visibility = ["//visibility:private"],
)

bzl_library(
    name = "tags_bzl",
    srcs = ["tags.bzl"],
    visibility = ["//visibility:private"],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
)

config_setting(
    name = "linux_arm64_cross",
    values = {
        "cpu": "aarch64",
        "host_cpu": "k8",
    },
    visibility = ["//visibility:private"],
)

config_setting(
    name = "linux_amd64_cross",
    values = {
        "cpu": "k8",
        "host_cpu": "aarch64",
    },
    visibility = ["//visibility:private"],
)

genrule(
    name = "version",
    outs = ["version.txt"],
    cmd = "cat bazel-out/stable-status.txt | grep STABLE_VERSION | cut -d' ' -f2- | sed 's/^[^[:digit:]]*//g' >$@",
    stamp = True,
    tags = [
        "manual",
        "nobuilder",
        "notap",
    ],
    visibility = ["//:sandbox"],
)

go_proto_library(
    name = "worker_protocol_go_proto",
    importpath = "gvisor.dev/bazel/worker_protocol_go_proto",
    proto = "@bazel_tools//src/main/protobuf:worker_protocol_proto",
)
