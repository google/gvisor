load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "ib",
    srcs = ["ib.go"],
    hostlayout = True,
    marshal = True,
    visibility = [
        "//pkg/sentry:internal",
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/marshal",
    ],
)
