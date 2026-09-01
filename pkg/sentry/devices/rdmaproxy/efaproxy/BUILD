load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "efaproxy",
    srcs = [
        "efaproxy.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/abi/ib",
        "//pkg/sentry/devices/rdmaproxy",
        "//pkg/sentry/kernel",
    ],
)
