load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "cpuid",
    srcs = [
        "cpu_amd64.s",
        "cpuid.go",
        "cpuid_arm64_unsafe.go",
        "cpuid_x86.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/cpuid",
    visibility = ["//:sandbox"],
    deps = ["//pkg/log"],
)

go_test(
    name = "cpuid_test",
    size = "small",
    srcs = [
        "cpuid_arm64_test.go",
        "cpuid_x86_test.go",
    ],
    embed = [":cpuid"],
)

go_test(
    name = "cpuid_parse_test",
    size = "small",
    srcs = [
        "cpuid_parse_x86_test.go",
    ],
    embed = [":cpuid"],
    tags = ["manual"],
)
