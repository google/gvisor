load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "syscalldocs",
    srcs = ["main.go"],
    visibility = ["//website:__pkg__"],
    deps = [
        "@org_golang_x_text//cases:go_default_library",
        "@org_golang_x_text//language:go_default_library",
    ],
)
