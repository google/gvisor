load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "go_merge",
    srcs = ["main.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//tools/tags",
    ],
)
