load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "proctor",
    srcs = ["main.go"],
    pure = True,
    visibility = ["//test/runtimes:__pkg__"],
    deps = [
        "//test/runtimes/proctor/lib",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
