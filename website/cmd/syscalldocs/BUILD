load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "syscalldocs",
    srcs = ["main.go"],
    visibility = ["//website:__pkg__"],
)
