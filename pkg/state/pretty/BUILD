load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "pretty",
    srcs = ["pretty.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/state",
        "//pkg/state/wire",
    ],
)
