load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "workload",
    srcs = ["workload.go"],
    visibility = ["//test/fuse_host:__pkg__"],
    deps = [
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
