load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "pprof",
    srcs = ["pprof.go"],
    visibility = [
        "//runsc:__subpackages__",
    ],
)
