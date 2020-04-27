load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "procid",
    srcs = [
        "procid.go",
        "procid_amd64.s",
        "procid_arm64.s",
    ],
    visibility = ["//visibility:public"],
)

go_test(
    name = "procid_test",
    size = "small",
    srcs = [
        "procid_test.go",
    ],
    library = ":procid",
    deps = ["//pkg/sync"],
)

go_test(
    name = "procid_net_test",
    size = "small",
    srcs = [
        "procid_net_test.go",
        "procid_test.go",
    ],
    library = ":procid",
    deps = ["//pkg/sync"],
)
