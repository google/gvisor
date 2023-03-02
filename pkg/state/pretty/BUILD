load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "pretty",
    srcs = ["pretty.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/state",
        "//pkg/state/wire",
    ],
)
