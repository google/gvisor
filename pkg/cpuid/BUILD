load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "cpuid",
    srcs = [
        "cpuid.go",
        "cpuid_amd64.go",
        "cpuid_arm64.go",
        "features_amd64.go",
        "features_arm64.go",
        "native_amd64.go",
        "native_amd64.s",
        "native_arm64.go",
        "static_amd64.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
    ],
)

go_test(
    name = "cpuid_test",
    size = "small",
    srcs = [
        "cpuid_amd64_test.go",
        "cpuid_test.go",
    ],
    library = ":cpuid",
)

go_test(
    name = "cpuid_parse_test",
    size = "small",
    srcs = [
        "cpuid_parse_amd64_test.go",
        "cpuid_parse_arm64_test.go",
        "cpuid_parse_test.go",
    ],
    library = ":cpuid",
    tags = ["manual"],
    deps = ["//pkg/hostos"],
)
