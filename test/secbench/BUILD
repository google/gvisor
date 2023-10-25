load("//tools:defs.bzl", "bzl_library", "go_binary", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "secbench",
    testonly = 1,
    srcs = ["secbench.go"],
    data = [
        ":runner",
    ],
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bpf",
        "//pkg/seccomp",
        "//pkg/test/testutil",
        "//test/secbench/secbenchdef",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_binary(
    name = "runner",
    testonly = 1,
    srcs = ["runner.go"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bpf",
        "//pkg/gohacks",
        "//pkg/seccomp",
        "//test/secbench/secbenchdef",
    ],
)

bzl_library(
    name = "defs",
    srcs = ["defs.bzl"],
    deps = ["//tools:defs_bzl"],
)
