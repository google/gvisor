load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "cxproxy",
    srcs = [
        "cxproxy.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/abi/ib",
        "//pkg/cleanup",
        "//pkg/hostarch",
        "//pkg/sentry/devices/rdmaproxy",
        "//pkg/sentry/kernel",
    ],
)
