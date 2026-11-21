load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "genlinuxsyscalls",
    srcs = ["genlinuxsyscalls.go"],
    visibility = ["//pkg/sentry/syscalls/linux:__pkg__"],
)
