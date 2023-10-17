load("//tools:defs.bzl", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "dumpfilter",
    srcs = [
        "dumpfilter.go",
        "dumpfilter_unsafe.go",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bpf",
        "//pkg/log",
        "//pkg/seccomp",
        "//pkg/sentry/platform/systrap",
        "//runsc/boot/filter",
        "//runsc/flag",
    ],
)

go_test(
    name = "dumpfilter_test",
    srcs = ["dumpfilter_test.go"],
    data = [":dumpfilter"],
    deps = ["//pkg/test/testutil"],
)
