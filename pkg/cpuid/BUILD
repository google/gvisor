load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "cpuid",
    srcs = [
        "cpu_amd64.s",
        "cpuid.go",
    ],
    visibility = ["//:sandbox"],
    deps = ["//pkg/log"],
)

go_test(
    name = "cpuid_test",
    size = "small",
    srcs = ["cpuid_test.go"],
    library = ":cpuid",
)

go_test(
    name = "cpuid_parse_test",
    size = "small",
    srcs = [
        "cpuid_parse_test.go",
    ],
    library = ":cpuid",
    tags = ["manual"],
)
