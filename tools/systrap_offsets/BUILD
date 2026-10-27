load("//tools:defs.bzl", "go_binary")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_binary(
    name = "gen_offsets",
    srcs = ["main.go"],
    pure = True,
    visibility = ["//pkg/sentry/platform/systrap/sysmsg:__pkg__"],
)
