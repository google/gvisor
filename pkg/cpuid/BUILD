load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

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
        "//pkg/sync",
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
    # NOTE: It seems that bazel code generation does not properly parse tags
    # when run via the architecture transition for nogo. This should be fixed
    # at some point in the future, but for now we can simply skip nogo analysis
    # on the test itself. It still applies to the core library.
    nogo = False,
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
