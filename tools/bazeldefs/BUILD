load("//tools:defs.bzl", "bzl_library")
load(":go.bzl", "go_cov_toolchain")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

bzl_library(
    name = "platforms_bzl",
    srcs = ["platforms.bzl"],
    visibility = ["//:sandbox"],
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
    deps = [
        "@bazel_skylib//rules/directory:providers",
        "@rules_cc//cc/common",
    ],
)

bzl_library(
    name = "go_bzl",
    srcs = ["go.bzl"],
    visibility = ["//visibility:private"],
    deps = [":defs_bzl"],
)

# Keep Go's pure/cgo mode in its build settings, not the target platform:
# Bazel 9 also uses target constraints to select a test execution platform.
platform(
    name = "linux_amd64",
    constraint_values = [
        "@platforms//cpu:x86_64",
        "@platforms//os:linux",
    ],
    visibility = ["//visibility:public"],
)

platform(
    name = "linux_arm64",
    constraint_values = [
        "@platforms//cpu:aarch64",
        "@platforms//os:linux",
    ],
    visibility = ["//visibility:public"],
)

config_setting(
    name = "amd64",
    constraint_values = [
        "@platforms//cpu:x86_64",
    ],
)

config_setting(
    name = "arm64",
    constraint_values = [
        "@platforms//cpu:aarch64",
    ],
)

config_setting(
    name = "riscv64",
    constraint_values = [
        "@platforms//cpu:riscv64",
    ],
)

genrule(
    name = "version",
    outs = ["version.txt"],
    cmd = "cat bazel-out/stable-status.txt | grep STABLE_VERSION | cut -d' ' -f2- | sed 's/^[^[:digit:]]*//g' >$@",
    stamp = 1,
    tags = [
        "manual",
        "nobuilder",
        "notap",
    ],
    visibility = ["//:sandbox"],
)

toolchain_type(
    name = "go_cov_toolchain_type",
    visibility = ["//visibility:public"],
)

go_cov_toolchain(name = "go_cov_toolchain")

toolchain(
    name = "go_cov_amd64_toolchain",
    exec_compatible_with = ["@platforms//cpu:x86_64"],
    target_compatible_with = ["@platforms//cpu:x86_64"],
    toolchain = ":go_cov_toolchain",
    toolchain_type = ":go_cov_toolchain_type",
)

toolchain(
    name = "go_cov_arm64_toolchain",
    exec_compatible_with = ["@platforms//cpu:aarch64"],
    target_compatible_with = ["@platforms//cpu:aarch64"],
    toolchain = ":go_cov_toolchain",
    toolchain_type = ":go_cov_toolchain_type",
)
