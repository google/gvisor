load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "urpc",
    srcs = ["urpc.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/fd",
        "//pkg/log",
        "//pkg/sync",
        "//pkg/unet",
    ],
)

go_test(
    name = "urpc_test",
    size = "small",
    srcs = ["urpc_test.go"],
    library = ":urpc",
    deps = ["//pkg/unet"],
)
