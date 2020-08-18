load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "wire",
    srcs = ["wire.go"],
    marshal = False,
    stateify = False,
    visibility = ["//:sandbox"],
    deps = ["//pkg/gohacks"],
)
