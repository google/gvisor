package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "cpuid",
    srcs = [
        "cpu_amd64.s",
        "cpuid.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/cpuid",
    visibility = ["//:sandbox"],
    deps = ["//pkg/log"],
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
