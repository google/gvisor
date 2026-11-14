load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "report",
    srcs = ["main.go"],
    pure = True,
    visibility = ["//tools:__pkg__"],
)
