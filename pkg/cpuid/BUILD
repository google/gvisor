load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "cpuid",
    srcs = [
        "cpu_amd64.s",
        "cpuid.go",
        "cpuid_arm64.go",
        "cpuid_x86.go",
    ],
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
    library = ":cpuid",
)

go_test(
    name = "cpuid_parse_test",
    size = "small",
    srcs = [
        "cpuid_parse_x86_test.go",
    ],
    library = ":cpuid",
    tags = ["manual"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
