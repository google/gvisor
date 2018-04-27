package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "cpuid_state",
    srcs = ["cpuid.go"],
    out = "cpuid_state.go",
    package = "cpuid",
)

go_library(
    name = "cpuid",
    srcs = [
        "cpu_amd64.s",
        "cpuid.go",
        "cpuid_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/cpuid",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/state",
    ],
)

go_test(
    name = "cpuid_test",
    size = "small",
    srcs = ["cpuid_test.go"],
    embed = [":cpuid"],
)

go_test(
    name = "cpuid_parse_test",
    size = "small",
    srcs = [
        "cpuid_parse_test.go",
    ],
    embed = [":cpuid"],
    tags = ["manual"],
)
