load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "device",
    srcs = ["device.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/sync",
    ],
)

go_test(
    name = "device_test",
    size = "small",
    srcs = ["device_test.go"],
    library = ":device",
)
